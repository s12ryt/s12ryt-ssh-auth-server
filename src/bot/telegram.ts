import { Bot, InlineKeyboard } from "grammy";

import type { BotController, BotReply, BotUpdate } from "./controller.js";

interface TelegramContextLike {
  from: { id: number; language_code?: string | undefined } | undefined;
  chat: { type: string } | undefined;
  message: { message_id: number; text?: string | undefined } | undefined;
  callbackQuery: { id: string; data?: string | undefined } | undefined;
  deleteMessage(): Promise<unknown>;
  reply(text: string, options?: unknown): Promise<unknown>;
  answerCallbackQuery(): Promise<unknown>;
}

interface BotControllerLike {
  handle(update: BotUpdate): Promise<BotReply[]>;
}

export function createTelegramBot(
  token: string,
  controller: BotController,
): Bot {
  const bot = new Bot(token);
  bot.on(["message:text", "callback_query:data"], async (context) => {
    await dispatchTelegramUpdate(context, controller);
  });
  return bot;
}

export async function dispatchTelegramUpdate(
  context: TelegramContextLike,
  controller: BotControllerLike,
): Promise<void> {
  if (!context.from || !context.chat) return;
  const update: BotUpdate = {
    telegramUserId: context.from.id,
    chatType: context.chat.type,
  };
  if (context.from.language_code)
    update.languageCode = context.from.language_code;
  if (context.message?.text) update.text = context.message.text;
  if (context.callbackQuery?.data)
    update.callbackData = context.callbackQuery.data;

  const replies = await controller.handle(update);
  let deleted = false;
  for (const reply of replies) {
    if (reply.deleteIncoming && context.message && !deleted) {
      deleted = true;
      await context.deleteMessage().catch(() => undefined);
    }
    const keyboard = reply.keyboard ? buildKeyboard(reply.keyboard) : undefined;
    await context.reply(
      reply.text,
      keyboard ? { reply_markup: keyboard } : undefined,
    );
  }
  if (context.callbackQuery) {
    await context.answerCallbackQuery().catch(() => undefined);
  }
}

function buildKeyboard(
  rows: NonNullable<BotReply["keyboard"]>,
): InlineKeyboard {
  const keyboard = new InlineKeyboard();
  rows.forEach((row, rowIndex) => {
    if (rowIndex > 0) keyboard.row();
    for (const button of row) {
      keyboard.text(button.text, button.data);
    }
  });
  return keyboard;
}
