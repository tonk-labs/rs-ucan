pub struct Signed<T, S> {
    varsig_header: (),
    payload: T,
    signature: S,
}
