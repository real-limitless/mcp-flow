/** Access token is "expiring" when it ends inside this window. */
export const EXPIRING_WINDOW_MS = 5 * 60 * 1000;

/** Refresh before the access token actually expires. */
export const REFRESH_SKEW_MS = 60 * 1000;

/** Consent state is single-use and short-lived. */
export const PENDING_STATE_MS = 10 * 60 * 1000;
