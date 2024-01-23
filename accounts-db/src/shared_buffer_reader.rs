//! SharedBuffer is given a Reader and SharedBufferReader implements the Reader trait.
//! SharedBuffer reads ahead in the underlying file and saves the data.
//! SharedBufferReaders can be created for the buffer and independently keep track of each reader's read location.
//! The background reader keeps track of the progress of each client. After data has been read by all readers,
//!  the buffer is recycled and reading ahead continues.
//! A primary use case is the underlying reader being decompressing a file, which can be computationally expensive.
//! The clients of SharedBufferReaders could be parallel instances which need access to the decompressed data.
use {
    crate::waitable_condvar::WaitableCondvar,
    log::*,
    solana_measure::measure::Measure,
    std::{
        io::*,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, RwLock,
        },
        thread::{Builder, JoinHandle},
        time::Duration,
    },
};

// tunable parameters:
// # bytes allocated and populated by reading ahead
const TOTAL_BUFFER_BUDGET_DEFAULT: usize = 2_000_000_000;
// data is read-ahead and saved in chunks of this many bytes
const CHUNK_SIZE_DEFAULT: usize = 100_000_000;

type OneSharedBuffer = Arc<Vec<u8>>;

struct SharedBufferInternal {
    bg_reader_data: Arc<SharedBufferBgReader>,

    bg_reader_join_handle: Mutex<Option<JoinHandle<()>>>,

    // Keep track of the next read location per outstanding client.
    // index is client's my_client_index.
    // Value at index is index into buffers where that client is currently reading.
    // Any buffer at index < min(clients) can be recycled or destroyed.
    clients: RwLock<Vec<usize>>,

    // unpacking callers read from 'data'. newly_read_data is transferred to 'data when 'data' is exhausted.
    // This minimizes lock contention since bg file reader has to have almost constant write access.
    data: RwLock<Vec<OneSharedBuffer>>,

    // it is convenient to have one of these around
    empty_buffer: OneSharedBuffer,
}

pub struct SharedBuffer {
    instance: Arc<SharedBufferInternal>,
}

impl SharedBuffer {
    pub fn new<T: 'static + Read + std::marker::Send>(reader: T) -> Self {
        Self::new_with_sizes(TOTAL_BUFFER_BUDGET_DEFAULT, CHUNK_SIZE_DEFAULT, reader)
    }
    fn new_with_sizes<T: 'static + Read + std::marker::Send>(
        total_buffer_budget: usize,
        chunk_size: usize,
        reader: T,
    ) -> Self {
        assert!(total_buffer_budget > 0);
        assert!(chunk_size > 0);
        let instance = SharedBufferInternal {
            bg_reader_data: Arc::new(SharedBufferBgReader::new()),
            data: RwLock::new(vec![OneSharedBuffer::default()]), // initialize with 1 vector of empty data at data[0]

            // default values
            bg_reader_join_handle: Mutex::default(),
            clients: RwLock::default(),
            empty_buffer: OneSharedBuffer::default(),
        };
        let instance = Arc::new(instance);
        let bg_reader_data = instance.bg_reader_data.clone();

        let handle = Builder::new()
            .name("solCompFileRead".to_string())
            .spawn(move || {
                // importantly, this thread does NOT hold a refcount on the arc of 'instance'
                bg_reader_data.read_entire_file_in_bg(reader, total_buffer_budget, chunk_size);
            });
        *instance.bg_reader_join_handle.lock().unwrap() = Some(handle.unwrap());
        Self { instance }
    }
}

pub struct SharedBufferReader {
    instance: Arc<SharedBufferInternal>,
    my_client_index: usize,
    // index in 'instance' of the current buffer this reader is reading from.
    // The current buffer is referenced from 'current_data'.
    // Until we exhaust this buffer, we don't need to get a lock to read from this.
    current_buffer_index: usize,
    // the index within current_data where we will next read
    index_in_current_data: usize,
    current_data: OneSharedBuffer,

    // convenient to have access to
    empty_buffer: OneSharedBuffer,
}

impl Drop for SharedBufferInternal {
    fn drop(&mut self) {
        if let Some(handle) = self.bg_reader_join_handle.lock().unwrap().take() {
            self.bg_reader_data.stop.store(true, Ordering::Relaxed);
            handle.join().unwrap();
        }
    }
}

impl Drop for SharedBufferReader {
    fn drop(&mut self) {
        self.client_done_reading();
    }
}

#[derive(Debug)]
struct SharedBufferBgReader {
    stop: AtomicBool,
    // error encountered during read
    error: RwLock<std::io::Result<usize>>,
    // bg thread reads to 'newly_read_data' and signals
    newly_read_data: RwLock<Vec<OneSharedBuffer>>,
    // set when newly_read_data gets new data written to it and can be transferred
    newly_read_data_signal: WaitableCondvar,

    // currently available set of buffers for bg to read into
    // during operation, this is exhausted as the bg reads ahead
    // As all clients are done with an earlier buffer, it is recycled by being put back into this vec for the bg thread to pull out.
    buffers: RwLock<Vec<OneSharedBuffer>>,
    // signaled when a new buffer is added to buffers. This throttles the bg reading.
    new_buffer_signal: WaitableCondvar,

    bg_eof_reached: AtomicBool,
}

impl SharedBufferBgReader {
    fn new() -> Self {
        SharedBufferBgReader {
            buffers: RwLock::new(vec![]),
            error: RwLock::new(Ok(0)),

            // easy defaults
            stop: AtomicBool::new(false),
            newly_read_data: RwLock::default(),
            newly_read_data_signal: WaitableCondvar::default(),
            new_buffer_signal: WaitableCondvar::default(),
            bg_eof_reached: AtomicBool::default(),
        }
    }

    fn default_wait_timeout() -> Duration {
        Duration::from_millis(100) // short enough to be unnoticable in case of trouble, long enough for efficient waiting
    }
    fn wait_for_new_buffer(&self) -> bool {
        self.new_buffer_signal
            .wait_timeout(Self::default_wait_timeout())
    }
    fn num_buffers(total_buffer_budget: usize, chunk_size: usize) -> usize {
        std::cmp::max(1, total_buffer_budget / chunk_size) // at least 1 buffer
    }
    fn set_error(&self, error: std::io::Error) {
        *self.error.write().unwrap() = Err(error);
        self.newly_read_data_signal.notify_all(); // any client waiting for new data needs to wake up and check for errors
    }

    // read ahead the entire file.
    // This is governed by the supply of buffers.
    // Buffers are likely limited to cap memory usage.
    // A buffer is recycled after the last client finishes reading from it.
    // When a buffer is available (initially or recycled), this code wakes up and reads into that buffer.
    fn read_entire_file_in_bg<T: 'static + Read + std::marker::Send>(
        &self,
        mut reader: T,
        total_buffer_budget: usize,
        chunk_size: usize,
    ) {
        let now = std::time::Instant::now();
        let mut read_us = 0;

        let mut max_bytes_read = 0;
        let mut wait_us = 0;
        let mut total_bytes = 0;
        let mut error = SharedBufferReader::default_error();
        let mut remaining_buffers_to_allocate = Self::num_buffers(total_buffer_budget, chunk_size);
        loop {
            if self.stop.load(Ordering::Relaxed) {
                // unsure what error is most appropriate here.
                // bg reader was told to stop. All clients need to see that as an error if they try to read.
                self.set_error(std::io::Error::from(std::io::ErrorKind::TimedOut));
                break;
            }
            let mut buffers = self.buffers.write().unwrap();
            let buffer = buffers.pop();
            drop(buffers);
            let mut dest_data = if let Some(dest_data) = buffer {
                // assert that this should not result in a vector copy
                // These are internal buffers and should not be held by anyone else.
                assert_eq!(Arc::strong_count(&dest_data), 1);
                dest_data
            } else if remaining_buffers_to_allocate > 0 {
                // we still haven't allocated all the buffers we are allowed to allocate
                remaining_buffers_to_allocate -= 1;
                Arc::new(vec![0; chunk_size])
            } else {
                // nowhere to write, so wait for a buffer to become available
                let mut wait_for_new_buffer = Measure::start("wait_for_new_buffer");
                self.wait_for_new_buffer();
                wait_for_new_buffer.stop();
                wait_us += wait_for_new_buffer.as_us();
                continue; // check stop, try to get a buffer again
            };
            let target = Arc::make_mut(&mut dest_data);
            let dest_size = target.len();

            let mut bytes_read = 0;
            let mut eof = false;
            let mut error_received = false;

            while bytes_read < dest_size {
                let mut time_read = Measure::start("read");
                // Read from underlying reader into the remaining range in dest_data
                // Note that this read takes less time (up to 2x) if we read into the same static buffer location each call.
                // But, we have to copy the data out later, so we choose to pay the price at read time to put the data where it is useful.
                let result = reader.read(&mut target[bytes_read..]);
                time_read.stop();
                read_us += time_read.as_us();
                match result {
                    Ok(size) => {
                        if size == 0 {
                            eof = true;
                            break;
                        }
                        total_bytes += size;
                        max_bytes_read = std::cmp::max(max_bytes_read, size);
                        bytes_read += size;
                        // loop to read some more. Underlying reader does not usually read all we ask for.
                    }
                    Err(err) => {
                        error_received = true;
                        error = err;
                        break;
                    }
                }
            }

            if bytes_read > 0 {
                // store this buffer in the bg data list
                target.truncate(bytes_read);
                let mut data = self.newly_read_data.write().unwrap();
                data.push(dest_data);
                drop(data);
                self.newly_read_data_signal.notify_all();
            }

            if eof {
                self.bg_eof_reached.store(true, Ordering::Relaxed);
                self.newly_read_data_signal.notify_all(); // anyone waiting for new data needs to know that we reached eof
                break;
            }

            if error_received {
                // do not ask for more data from 'reader'. We got an error and saved all the data we got before the error.
                // but, wait to set error until we have added our buffer to newly_read_data
                self.set_error(error);
                break;
            }
        }

        info!(
            "reading entire decompressed file took: {} us, bytes: {}, read_us: {}, waiting_for_buffer_us: {}, largest fetch: {}, error: {:?}",
            now.elapsed().as_micros(),
            total_bytes,
            read_us,
            wait_us,
            max_bytes_read,
            self.error.read().unwrap()
        );
    }
}

impl SharedBufferInternal {
    fn wait_for_newly_read_data(&self) -> bool {
        self.bg_reader_data
            .newly_read_data_signal
            .wait_timeout(SharedBufferBgReader::default_wait_timeout())
    }
    // bg reader uses write lock on 'newly_read_data' each time a buffer is read or recycled
    // client readers read from 'data' using read locks
    // when all of 'data' has been exhausted by clients, 1 client needs to transfer from 'newly_read_data' to 'data' one time.
    // returns true if any data was added to 'data'
    fn transfer_data_from_bg(&self) -> bool {
        let mut from_lock = self.bg_reader_data.newly_read_data.write().unwrap();
        if from_lock.is_empty() {
            // no data available from bg
            return false;
        }
        // grab all data from bg
        let mut newly_read_data: Vec<OneSharedBuffer> = std::mem::take(&mut *from_lock);
        // append all data to fg
        let mut to_lock = self.data.write().unwrap();
        // from_lock has to be held until we have the to_lock lock. Otherwise, we can race with another reader and append to to_lock out of order.
        drop(from_lock);
        to_lock.append(&mut newly_read_data);
        true // data was transferred
    }
    fn has_reached_eof(&self) -> bool {
        self.bg_reader_data.bg_eof_reached.load(Ordering::Relaxed)
    }
}

// only public methods are new and from trait Read
impl SharedBufferReader {
    pub fn new(original_instance: &SharedBuffer) -> Self {
        let original_instance = &original_instance.instance;
        let current_buffer_index = 0;
        let mut list = original_instance.clients.write().unwrap();
        let my_client_index = list.len();
        if my_client_index > 0 {
            let current_min = list.iter().min().unwrap();
            if current_min > &0 {
                drop(list);
                panic!("SharedBufferReaders must all be created before the first one reads");
            }
        }
        list.push(current_buffer_index);
        drop(list);

        Self {
            instance: Arc::clone(original_instance),
            my_client_index,
            current_buffer_index,
            index_in_current_data: 0,
            // startup condition for our local reference to the buffer we want to read from.
            // data[0] will always exist. It will be empty, But that is ok. Corresponds to current_buffer_index initial value of 0.
            current_data: original_instance.data.read().unwrap()[0].clone(),
            empty_buffer: original_instance.empty_buffer.clone(),
        }
    }
    fn default_error() -> std::io::Error {
        // AN error
        std::io::Error::from(std::io::ErrorKind::TimedOut)
    }
    fn client_done_reading(&mut self) {
        // has the effect of causing nobody to ever again wait on this reader's progress
        self.update_client_index(usize::MAX);
    }

    // this client will now be reading from current_buffer_index
    // We may be able to recycle the buffer(s) this client may have been previously potentially using.
    fn update_client_index(&mut self, new_buffer_index: usize) {
        let previous_buffer_index = self.current_buffer_index;
        self.current_buffer_index = new_buffer_index;
        let client_index = self.my_client_index;
        let mut indexes = self.instance.clients.write().unwrap();
        indexes[client_index] = new_buffer_index;
        drop(indexes);
        let mut new_min = *self.instance.clients.read().unwrap().iter().min().unwrap();
        // if new_min == usize::MAX, then every caller is done reading. We could shut down the bg reader and effectively drop everything.
        new_min = std::cmp::min(new_min, self.instance.data.read().unwrap().len());

        // if any buffer indexes are now no longer used by any readers, then this reader was the last reader holding onto some indexes.
        if new_min > previous_buffer_index {
            // if bg reader reached eof, there is no need to recycle any buffers and they can all be dropped
            let eof = self.instance.has_reached_eof();

            for recycle in previous_buffer_index..new_min {
                let remove = {
                    let mut data = self.instance.data.write().unwrap();
                    std::mem::replace(&mut data[recycle], self.empty_buffer.clone())
                };
                if remove.is_empty() {
                    continue; // another thread beat us swapping out this buffer, so nothing to recycle here
                }

                if !eof {
                    // if !eof, recycle this buffer and notify waiting reader(s)
                    // if eof, just drop buffer this buffer since it isn't needed for reading anymore
                    self.instance
                        .bg_reader_data
                        .buffers
                        .write()
                        .unwrap()
                        .push(remove);
                    self.instance.bg_reader_data.new_buffer_signal.notify_all();
                    // new buffer available for bg reader
                }
            }
        }
    }
}

impl Read for SharedBufferReader {
    // called many times by client to read small buffer lengths
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let dest_len = buf.len();
        let mut offset_in_dest = 0;

        let mut eof_seen = false;
        'outer: while offset_in_dest < dest_len {
            // this code is optimized for the common case where we can satisfy this entire read request from current_data without locks
            let source = &*self.current_data;

            let remaining_source_len = source.len() - self.index_in_current_data;
            let bytes_to_transfer = std::cmp::min(dest_len - offset_in_dest, remaining_source_len);
            // copy what we can
            buf[offset_in_dest..(offset_in_dest + bytes_to_transfer)].copy_from_slice(
                &source
                    [self.index_in_current_data..(self.index_in_current_data + bytes_to_transfer)],
            );
            self.index_in_current_data += bytes_to_transfer;
            offset_in_dest += bytes_to_transfer;

            if offset_in_dest >= dest_len {
                break;
            }

            // we exhausted the current buffer
            // increment current_buffer_index get the next buffer to continue reading
            self.current_data = self.empty_buffer.clone(); // unref it so it can be recycled without copy
            self.index_in_current_data = 0;
            self.update_client_index(self.current_buffer_index + 1);

            let instance = &*self.instance;
            let mut lock;
            // hang out in this loop until the buffer we need is available
            loop {
                lock = instance.data.read().unwrap();
                if self.current_buffer_index < lock.len() {
                    break;
                }
                drop(lock);

                if self.instance.transfer_data_from_bg() {
                    continue;
                }

                // another thread may have transferred data, so check again to see if we have data now
                lock = instance.data.read().unwrap();
                if self.current_buffer_index < lock.len() {
                    break;
                }
                drop(lock);

                if eof_seen {
                    // eof detected on previous iteration, we have had a chance to read all data that was buffered, and there is not enough for us
                    break 'outer;
                }

                // no data, we could not transfer, and still no data, so check for eof.
                // If we got an eof, then we have to check again for data to make sure there isn't data now that we may be able to transfer or read. Our reading can lag behind the bg read ahead.
                if instance.has_reached_eof() {
                    eof_seen = true;
                    continue;
                }

                {
                    // Since the bg reader could not satisfy our read, now is a good time to check to see if the bg reader encountered an error.
                    // Note this is a write lock because we want to get the actual error detected and return it here and avoid races with other readers if we tried a read and then subsequent write lock.
                    // This would be simpler if I could clone an io error.
                    let mut error = instance.bg_reader_data.error.write().unwrap();
                    if error.is_err() {
                        // replace the current error (with AN error instead of ok)
                        // return the original error
                        return std::mem::replace(&mut *error, Err(Self::default_error()));
                    }
                }

                // no data to transfer, and file not finished, but no error, so wait for bg reader to read some more data
                instance.wait_for_newly_read_data();
            }

            // refresh current_data inside the lock
            self.current_data = Arc::clone(&lock[self.current_buffer_index]);
        }
        Ok(offset_in_dest)
    }
}
