/// Measure this expression
///
/// Use `measure!()` when you have an expression that you want to measure.  `measure!()` will start
/// a new [`Measure`], evaluate your expression, stop the [`Measure`], and then return the
/// [`Measure`] object along with your expression's return value.
///
/// Use `measure_us!()` when you want to measure an expression in microseconds.
///
/// [`Measure`]: crate::measure::Measure
///
/// # Examples
///
/// ```
/// // Measure functions
/// # use solana_measure::{measure, measure_us};
/// # fn foo() {}
/// # fn bar(x: i32) {}
/// # fn add(x: i32, y: i32) -> i32 {x + y}
/// let (result, measure) = measure!(foo(), "foo takes no parameters");
/// let (result, measure) = measure!(bar(42), "bar takes one parameter");
/// let (result, measure) = measure!(add(1, 2), "add takes two parameters and returns a value");
/// let (result, measure_us) = measure_us!(add(1, 2));
/// # assert_eq!(result, 1 + 2);
/// ```
///
/// ```
/// // Measure methods
/// # use solana_measure::{measure, measure_us};
/// # struct Foo {
/// #     f: i32,
/// # }
/// # impl Foo {
/// #     fn frobnicate(&self, bar: i32) -> i32 {
/// #         self.f * bar
/// #     }
/// # }
/// let foo = Foo { f: 42 };
/// let (result, measure) = measure!(foo.frobnicate(2), "measure methods");
/// let (result, measure_us) = measure_us!(foo.frobnicate(2));
/// # assert_eq!(result, 42 * 2);
/// ```
///
/// ```
/// // Measure expression blocks
/// # use solana_measure::measure;
/// # fn complex_calculation() -> i32 { 42 }
/// # fn complex_transform(x: i32) -> i32 { x + 3 }
/// # fn record_result(y: i32) {}
/// let (result, measure) = measure!(
///     {
///         let x = complex_calculation();
///         # assert_eq!(x, 42);
///         let y = complex_transform(x);
///         # assert_eq!(y, 42 + 3);
///         record_result(y);
///         y
///     },
///     "measure a block of many operations",
/// );
/// # assert_eq!(result, 42 + 3);
/// ```
///
/// ```
/// // The `name` parameter is optional
/// # use solana_measure::{measure, measure_us};
/// # fn meow() {};
/// let (result, measure) = measure!(meow());
/// let (result, measure_us) = measure_us!(meow());
/// ```
#[macro_export]
macro_rules! measure {
    ($val:expr, $name:tt $(,)?) => {{
        let mut measure = $crate::measure::Measure::start($name);
        let result = $val;
        measure.stop();
        (result, measure)
    }};
    ($val:expr) => {
        measure!($val, "")
    };
}

#[macro_export]
macro_rules! measure_us {
    ($val:expr) => {{
        let start = std::time::Instant::now();
        let result = $val;
        (result, solana_sdk::timing::duration_as_us(&start.elapsed()))
    }};
}
