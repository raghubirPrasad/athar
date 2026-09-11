import { createContext } from "react";

export type ToastTone = "info" | "success" | "warn" | "danger";

export interface Toast {
  id: number;
  title: string;
  detail?: string;
  tone: ToastTone;
}

export interface ToastInput {
  title: string;
  detail?: string;
  tone?: ToastTone;
  /** Milliseconds before auto-dismiss; 0 keeps it until dismissed. */
  duration?: number;
}

export interface ToastContextValue {
  toasts: readonly Toast[];
  push: (toast: ToastInput) => number;
  dismiss: (id: number) => void;
}

export const ToastContext = createContext<ToastContextValue | null>(null);
