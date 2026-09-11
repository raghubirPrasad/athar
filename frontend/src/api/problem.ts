import { isApiError, type ProblemDetails } from "./client";

/**
 * Coerce anything thrown — an ApiError, a raw problem+json object, a network
 * TypeError — into a problem shape the UI can render. Never surfaces a stack.
 */
export function toProblem(err: unknown): ProblemDetails {
  if (isApiError(err)) return err.toProblem();
  if (typeof err === "object" && err !== null && typeof (err as ProblemDetails).title === "string") {
    return err as ProblemDetails;
  }
  if (err instanceof Error) return { title: "Request failed", detail: err.message, code: "network_error" };
  return { title: "Something went wrong", code: "unknown" };
}
