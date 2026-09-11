import { useEffect } from "react";
import { APP_NAME } from "../branding";

/** Sets `document.title` to "<title> · ATHAR" while the component is mounted. */
export function usePageTitle(title: string): void {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · ${APP_NAME}` : APP_NAME;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
