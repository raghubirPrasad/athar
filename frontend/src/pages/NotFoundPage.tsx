import { ButtonLink } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeader } from "../components/ui/PageHeader";

export function NotFoundPage() {
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Page not found" />
      <EmptyState
        title="No such page"
        description="The address does not match any section of the dashboard."
        action={<ButtonLink to="/" variant="primary">Go to the overview</ButtonLink>}
      />
    </div>
  );
}
