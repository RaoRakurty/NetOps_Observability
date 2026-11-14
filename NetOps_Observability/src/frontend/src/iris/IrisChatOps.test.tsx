// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import IrisChatOps from "./IrisChatOps";
import { api, type ChatConnection, type ChatLink } from "../services/api";

afterEach(() => vi.restoreAllMocks());

const slackConn: ChatConnection = {
  platform: "slack", workspace_id: "T0ALPHA", app_id: "", public_url: "https://correlix.example.com",
  channel_replies: "private", enabled: true, has_signing_secret: true, has_bot_token: true, has_app_password: false,
  webhook_url: "/api/chatops/slack/abc123", updated_by: "carol", updated_at: "2026-11-14T10:00:00Z",
};
const pendingLink: ChatLink = {
  id: "l-1", platform: "slack", workspace_id: "T0ALPHA", chat_user_id: "U1",
  chat_name: "<b>mallory</b>", user_id: "alice", status: "pending", requested_at: "2026-11-14T10:00:00Z",
};

describe("IrisChatOps", () => {
  it("links a chat account with the code from the chat", async () => {
    vi.spyOn(api, "myChatLinks").mockResolvedValue({ links: [] });
    vi.spyOn(api, "chatConnections").mockRejectedValue(new Error("403 Forbidden: forbidden"));
    const redeem = vi.spyOn(api, "redeemChatCode").mockResolvedValue({ ...pendingLink, chat_name: "Alice" });
    render(<IrisChatOps />);
    await waitFor(() => expect(screen.getByText(/Workspace admins connect chat apps/)).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Code from Iris"), { target: { value: " abcd-efgh " } });
    fireEvent.click(screen.getByRole("button", { name: "Link" }));
    await waitFor(() => expect(redeem).toHaveBeenCalledWith("abcd-efgh"));
    await waitFor(() => expect(screen.getByRole("status").textContent).toMatch(/workspace admin now approves it/));
  });

  it("shows an admin the connection without any secret and the pending link as text", async () => {
    vi.spyOn(api, "myChatLinks").mockResolvedValue({ links: [] });
    vi.spyOn(api, "chatConnections").mockResolvedValue({ switch_on: false, connections: [slackConn] });
    vi.spyOn(api, "chatLinks").mockResolvedValue({ links: [pendingLink] });
    const decide = vi.spyOn(api, "decideChatLink").mockResolvedValue({ ...pendingLink, status: "approved" });
    render(<IrisChatOps />);
    await waitFor(() => expect(screen.getByTestId("chat-admin")).toBeTruthy());
    expect(screen.getByTestId("chat-switch-off")).toBeTruthy();
    expect(screen.getByText(/\/api\/chatops\/slack\/abc123/)).toBeTruthy();
    expect(screen.getAllByText(/set — leave blank to keep/).length).toBe(2);
    const secretInputs = screen.getByTestId("chat-conn-slack").querySelectorAll('input[type="password"]');
    secretInputs.forEach((i) => expect((i as HTMLInputElement).value).toBe(""));
    // A hostile chat name renders as text.
    expect(screen.getByText(/<b>mallory<\/b>/)).toBeTruthy();
    expect(document.querySelector("b")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(decide).toHaveBeenCalledWith("l-1", true));
  });

  it("saves a Teams connection with the admin's fields", async () => {
    vi.spyOn(api, "myChatLinks").mockResolvedValue({ links: [] });
    vi.spyOn(api, "chatConnections").mockResolvedValue({ switch_on: true, connections: [] });
    vi.spyOn(api, "chatLinks").mockResolvedValue({ links: [] });
    const save = vi.spyOn(api, "saveChatConnection").mockResolvedValue({ ...slackConn, platform: "teams" });
    render(<IrisChatOps />);
    await waitFor(() => expect(screen.getByTestId("chat-conn-teams")).toBeTruthy());
    const teams = screen.getByTestId("chat-conn-teams");
    const inputs = teams.querySelectorAll("input");
    fireEvent.change(inputs[0], { target: { value: "72f988bf-86f1-41af-91ab-2d7cd011db47" } });
    fireEvent.change(inputs[1], { target: { value: "11111111-2222-3333-4444-555555555555" } });
    fireEvent.change(inputs[2], { target: { value: "app-password-value" } });
    const saveBtn = Array.from(teams.querySelectorAll("button")).find((b) => b.textContent === "Save")!;
    fireEvent.click(saveBtn);
    await waitFor(() => expect(save).toHaveBeenCalled());
    const [platform, body] = save.mock.calls[0];
    expect(platform).toBe("teams");
    expect(body.workspace_id).toBe("72f988bf-86f1-41af-91ab-2d7cd011db47");
    expect(body.app_password).toBe("app-password-value");
    expect(body.channel_replies).toBe("private");
  });
});
