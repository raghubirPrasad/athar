import type { EvalOut } from "../../api/types";
import { Card } from "../ui/Card";

/**
 * The same measurement in two registers (SPEC §17): the sentence a director
 * repeats in a board meeting, and the numbers an engineer checks. Both come from
 * the API — the page does not compose either one.
 */
export function RegisterCards({ result }: { result: EvalOut }) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title="For the board" subtitle="Director register">
        <p data-register="director" className="text-[15px] leading-7 text-fg">
          {result.director_sentence}
        </p>
      </Card>
      <Card title="For the engineer" subtitle="Engineer register">
        <p data-register="engineer" className="text-[15px] leading-7 text-fg">
          {result.engineer_sentence}
        </p>
      </Card>
    </div>
  );
}
