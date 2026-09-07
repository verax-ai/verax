export type Measured<T> =
  | { readonly measured: true; readonly value: T; readonly source: string }
  | { readonly measured: false; readonly why: string };

export function measured<T>(value: T, source: string): Measured<T> {
  return { measured: true, value, source };
}

export function unmeasured<T = never>(why: string): Measured<T> {
  return { measured: false, why };
}

export function isMeasured<T>(field: Measured<T>): field is Extract<Measured<T>, { measured: true }> {
  return field.measured === true;
}
