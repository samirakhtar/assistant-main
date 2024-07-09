import { serve } from "@hono/node-server";
import { cors } from "hono/cors";
import { Hono } from "hono";
import { CohereClient } from "cohere-ai";
import { drizzle } from "drizzle-orm/postgres-js";
import * as postgres from "postgres";
import { chats } from "./schema";
import Redis from "ioredis";
import { NetworkService } from "./network-service";
import { AssemblyAI } from "assemblyai";

const assembly = new AssemblyAI({
  apiKey: "9829e495066e418789278d45ea13eb03",
});

const tools = [
  {
    name: "lookupActivitiesSearch",
    description: `Search for all dns lookup activities between a given date range, each activity has details for the user and the domain they have looked up`,
    parameterDefinitions: {
      identityids: {
        type: "str",
        description: `The identity ids of users to search for, seperated by a comma. Names or emails are not valid inputs, only the identity ids`,
      },
      startDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
      endDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
      domain: {
        type: "str",
        description:
          "The domanins to search for, seperated by a comma. Must end with a valid tld, if not present then a .com before being given as input",
      },
      category: {
        type: "str",
        description: `The categories of acitivies to search for, seperated by a comma`,
      },
      verdict: {
        type: "str",
        description: `If the lookup was allowed or blocked`,
      },
    },
  },
  {
    name: "listInfectedLookups",
    description:
      "Retrive a list of infected domain lookup activies, each activity has details for the user and the website they have tried to visit which is infected",
    parameterDefinitions: {
      identityids: {
        type: "str",
        description: `The identity ids of users to search for, seperated by a comma. Names or emails are not valid inputs, only the identity ids`,
      },
      startDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
      endDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
    },
  },
  {
    name: "createDestinationList",
    description:
      "Create a destination list which allows or blocks certain domains",
    parameterDefinitions: {
      domain: {
        type: "str",
        description: "The domain to add to the destination list",
        required: true,
      },
    },
  },
  {
    name: "getTopThreatTypes",
    description: "Get the top threat types",
    parameterDefinitions: {
      startDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
      endDate: {
        type: "str",
        description:
          "The ISO date string for the end date of the infected activities",
        required: true,
      },
    },
  },
  {
    name: "getIdentityId",
    description: "Get the identity id for a user by its name or email",
    parameterDefinitions: {
      search: {
        type: "str",
        description: "The name or email of the user to search for",
      },
    },
  },
  {
    name: "getTopThreats",
    description: "Get the top threats",
    parameterDefinitions: {
      startDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
      endDate: {
        type: "str",
        description:
          "The ISO date string for the start date of the infected activities",
        required: true,
      },
    },
  },
];

const cohere = new CohereClient({
  token: "DXQdUYmXm1uDI1ahdbG2MAP8qWYdwEsNQNrYqudx",
});

const client = postgres(
  "postgresql://postgres.paimkeixeviztsooisie:ajHvkE5wOgzfnqUm@aws-0-ap-south-1.pooler.supabase.com:6543/postgres",
);
const db = drizzle(client);

const redis = new Redis(
  "rediss://default:AdszAAIncDEwMjFmNDc2Zjc2YTk0ZjE0OTM4ODU3ZjdiZDFlNjlhYnAxNTYxMTU@polished-orca-56115.upstash.io:6379",
);

const app = new Hono();
const service = new NetworkService();
app.use(cors());

app.delete("/chats", async (c) => {
  await db.delete(chats);
  return c.json({});
});

app.get("/chats", async (c) => {
  const storedChats = await db.select().from(chats).orderBy(chats.id);
  return c.json(storedChats);
});

app.post("/chat", async (c) => {
  let token = await redis.get("token");
  if (!token) {
    token = await service.generateToken();
    await redis.set("token", token!, "EX", 3500);
  }
  service.setToken(token!);
  const data = await c.req.blob();
  const transscript = await assembly.transcripts.transcribe({
    audio: data,
    custom_spelling: [{ from: ["fishing"], to: "Phishing" }],
    word_boost: [
      "CTR",
      "Command and Control",
      "Cryptomining",
      "DNS Tunneling VPN",
      "Dynamic DNS",
      "Malware",
      "Newly Seen Domains",
      "Phishing",
      "Potentially Harmful",
      "Secure X",
      "Adult",
      "Advertisements",
      "Alcohol",
      "Animals and Pets",
      "Arts",
      "Astrology",
      "Auctions",
    ],
  });
  const message = transscript.text;
  // const data = await c.req.json();
  // const message = data.message;
  const exitingChats = await db.select().from(chats);

  let userResponse = "";

  await db.transaction(async (tx) => {
    tx.insert(chats)
      .values({ message: message as string, isBot: false })
      .execute();

    let chat = await cohere.chat({
      preamble: `You're an agent which uses cisco umbrella to provide reports & insights about activities of the users browing the web. The tools given to you help you perform various operations. The user can ask you to perform operation which can be done by a single tool or combination of tools provided to you. You can also ask for help to know about the tools available to you. If you think the user is asking for a tool which is not available to you, you can ask the user to rephrase the question or to understand it better or respond with a message suggesting you're not capable of performing the operation as of now. Keep the following things in mind when generating the response:

      - The response must be clear and concise.
      - The response must not contain any tool names, tool descriptions, or any technical details. Since the user is interacting with an agent, the response should be in a conversational tone.
      - If the user asks for help, provide the details of the tools available to you, you can use the description of the tools to provide the details.
      - You are directly interacting with the user, so make sure to refer to the user as 'you' and the agent as 'I'.
      - If the user has given a partial input, you can ask the user to provide more details
      - If the parameters provided by the user are not valid, you can ask the user to provide valid parameters
      - Always refer to the paramater description of functions to validate the input provided by the user.
      - If the response from a tool call is empty, you should let the user know that there are no results available request
      - Never personal emails or any sensitive information in the response unless the user explicitly asks for it.

      The current date and time in ISO format is - ${new Date().toISOString()}
      Always use this date and time for any date references. If the date range is not provided assume the last 30 days as range

      The following acitvity categories are known to system, refer this to extract data from user interactions:
      - CTR
      - Command and Control
      - Cryptomining
      - DNS Tunneling VPN
      - Dynamic DNS
      - Malware
      - Newly Seen Domains
      - Phishing
      - Potentially Harmful
      - Secure X
      - Adult
      - Advertisements
      - Alcohol
      - Animals and Pets
      - Arts
      - Astrology
      - Auctions

      If the user gives any categories which are not present in this list, ask the user to clarify what they want and provide the list of categories known to the system.


      While genearting output, use markdown to format in the output wherever possible, if you have data you can present in a table format, use markdown to present the data in a table format.

      Note - Never include ids in the response to the user whatsoever. Never tell the user any internal identifers or any technical details about the system
      Note - When telling about action plans, never mention the tools names to the user, always use their descriptions to tell the users what can be done
        `,
      temperature: 0,
      chatHistory: exitingChats.map((chat) => ({
        message: chat.message || "",
        role: chat.isBot ? "CHATBOT" : "USER",
      })),
      tools: tools as any,
      message: message as string,
    });
    console.log(chat);
    // throw new Error("test");

    while (chat.toolCalls?.length) {
      console.log(chat);
      exitingChats.push({ message: message!, isBot: false, id: 1 });
      exitingChats.push({ message: chat.text, isBot: true, id: 1 });
      const toolResults = await Promise.all(
        chat.toolCalls?.map(async (toolCall) => {
          console.log(toolCall);
          try {
            const output = await (service as any)[toolCall.name](
              toolCall.parameters,
            );
            let toolRes: Array<Record<string, unknown>>;
            if (Array.isArray(output)) {
              toolRes = output;
            } else {
              toolRes = [output];
            }
            console.log(toolRes);
            return {
              call: {
                name: toolCall.name,
                parameters: toolCall.parameters || {},
              },
              outputs: toolRes,
            };
          } catch (error: any) {
            console.log(error);
            return {
              call: {
                name: toolCall.name,
                parameters: toolCall.parameters || {},
              },
              outputs: [{ error: error.response?.data || error.message }],
            };
          }
        }) || [],
      );
      try {
        chat = await cohere.chat({
          preamble: `You're an agent which uses cisco umbrella to provide reports & insights about activities of the users browing the web. The tools given to you help you perform various operations. The user can ask you to perform operation which can be done by a single tool or combination of tools provided to you. You can also ask for help to know about the tools available to you. If you think the user is asking for a tool which is not available to you, you can ask the user to provide more details to understand it better or respond with a message suggesting you're not capable of performing the operation as of now. Keep the following things in mind when generating the response:

            - The response must be clear and concise.
            - The response must not contain any tool names, tool descriptions, or any technical details. Since the user is interacting with an agent, the response should be in a conversational tone.
            - If the user asks for help, provide the details of the tools available to you, you can use the description of the tools to provide the details.
            - You are directly interacting with the user, so make sure to refer to the user as 'you' and the agent as 'I'.
            - If the user has given a partial input, you can ask the user to provide more details
            - If the parameters provided by the user are not valid, you can ask the user to provide valid parameters
            - Always refer to the paramater description of functions to validate the input provided by the user.
            - If the response from a tool call is empty, you should let the user know that there are no results available request
            - Never personal emails or any sensitive information in the response unless the user explicitly asks for it.

            The current date and time in ISO format is - ${new Date().toISOString()}
            Always use this date and time for any date references. If the date range is not provided assume the last 30 days as range

            The following acitvity categories are known to system, refer this to extract data from user interactions:
            - CTR
            - Command and Control
            - Cryptomining
            - DNS Tunneling VPN
            - Dynamic DNS
            - Malware
            - Newly Seen Domains
            - Phishing
            - Potentially Harmful
            - Secure X
            - Adult
            - Advertisements
            - Alcohol
            - Animals and Pets
            - Arts
            - Astrology
            - Auctions

            If the user gives any categories which are not present in this list, it could be because of two reasons, either there is a typo in the category name or the category is invalid. If its a minor spelling mistake fix it yourself, else ask the user for confimartion

            While genearting output, use markdown to format in the output wherever possible, if you have data you can present in a table format, use markdown to present the data in a table format.

            Note - Never include ids in the response to the user whatsoever. Never tell the user any internal identifers or any technical details about the system
            Note - When telling about action plans, never mention the tools names to the user, always use their descriptions to tell the users what can be done
          `,

          temperature: 0,
          tools: tools as any,
          chatHistory: exitingChats.map((chat) => ({
            message: chat.message || "",
            role: chat.isBot ? "CHATBOT" : "USER",
          })),
          toolResults,
          message: "",
        });
      } catch (error: any) {
        throw error;
      }
    }

    console.log(chat);

    userResponse = chat.text;

    tx.insert(chats).values({ message: chat.text, isBot: true }).execute();
  });

  return c.json({
    message: userResponse,
  });
});

const port = 3000;
console.log(`Server is running on port ${port}`);

serve({
  fetch: app.fetch,
  port,
});
