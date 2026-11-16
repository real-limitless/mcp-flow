import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { RequestOptions } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  ListToolsResultSchema,
  type ListToolsRequest,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * Upstream client whose tools/list does not compile an Ajv validator per output
 * schema. `Client.listTools` does that compile synchronously in
 * `cacheToolMetadata`. Across a fan-out the compiles run back-to-back on the
 * gateway event loop and /health misses its probe. The gateway forwards
 * structured tool output; it does not need those validators to list tools.
 */
export class ListingClient extends Client {
  override listTools(
    params?: ListToolsRequest["params"],
    options?: RequestOptions,
  ): ReturnType<Client["listTools"]> {
    return this.request(
      { method: "tools/list", params },
      ListToolsResultSchema,
      options,
    );
  }
}
