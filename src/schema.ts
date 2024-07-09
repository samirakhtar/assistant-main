import { pgTable, serial, text, boolean } from "drizzle-orm/pg-core";

export const chats = pgTable("chat", {
  id: serial("id").primaryKey(),
  message: text("message"),
  isBot: boolean("is_bot"),
});
