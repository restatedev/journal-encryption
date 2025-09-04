import { service, createServiceHandler, Context } from "@restatedev/restate-sdk";
import { serde } from "@restatedev/restate-sdk-zod";
import { z } from "zod";

export const greeter = service({
  name: "greeter",
  handlers: {
    greet: createServiceHandler(
      {
        input: serde.zod(
          z.object({
            name: z.string(),
          })
        ),
        output: serde.zod(
          z.object({
            message: z.string(),
          })
        ),
      },
      async (_context: Context, { name }) => {
        return { message: `Hello, ${name}!` };
      }
    ),
  },
});

export type GreeterType = typeof greeter;
