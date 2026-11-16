import { Link } from "react-router";
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/** An address with no page. */
export function Placeholder({ title, text }: { title: string; text: string }) {
  return (
    <Card className="mx-auto max-w-xl">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>
          {text}{" "}
          <Link to="/" className="underline underline-offset-4">
            Back to Home
          </Link>
        </CardDescription>
      </CardHeader>
    </Card>
  );
}
