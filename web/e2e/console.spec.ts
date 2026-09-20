import { test, expect } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

test("Owner manages keys, policies, settings and tokens through the real Go service", async ({
  page,
  context,
}) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (/Content Security Policy|Refused to/.test(message.text()))
      errors.push(message.text());
  });
  page.on("dialog", (dialog) => dialog.accept());
  const dialog = page.getByRole("dialog");
  const closeDialog = async () => {
    await dialog.getByRole("button", { name: "关闭", exact: true }).click();
  };
  await test.step("one-time setup and password login", async () => {
    const data = await readFile(resolve("../.dev/e2e-current"), "utf8");
    await page.goto("/setup");
    await page
      .getByLabel("初始化码")
      .fill((await readFile(resolve(data, "setup-token"), "utf8")).trim());
    await page.getByLabel("Owner 邮箱").fill("e2e@example.com");
    await page
      .getByLabel("密码", { exact: false })
      .fill("E2E-test-passphrase-2026");
    await page
      .getByRole("button", { name: "创建密钥空间", exact: true })
      .click();
    await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
    await page.getByLabel("Owner 邮箱").fill("e2e@example.com");
    await page
      .getByLabel("密码", { exact: true })
      .fill("E2E-test-passphrase-2026");
    await page.getByRole("button", { name: "登录", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "密钥", exact: true }),
    ).toBeVisible();
    expect(
      (await context.request.post("/v1/setup", { data: {} })).status(),
    ).toBe(409);
  });
  await test.step("create tag and encrypted key, assign tag and write new version", async () => {
    await page.getByRole("link", { name: "标签", exact: true }).click();
    await page
      .getByRole("button", { name: "创建标签", exact: true })
      .first()
      .click();
    await dialog.getByLabel("标签名称").fill("production");
    await dialog.getByRole("button", { name: "保存", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "production" }),
    ).toBeVisible();
    await page.getByRole("link", { name: "密钥", exact: true }).click();
    await page.getByRole("button", { name: "创建密钥", exact: true }).click();
    await dialog.getByLabel("密钥路径").fill("shared/npm-token");
    await dialog.getByLabel("密钥值").fill("synthetic-secret\nsecond line");
    await dialog.getByRole("button", { name: "创建密钥", exact: true }).click();
    await expect(
      page.getByRole("button", { name: "shared/npm-token", exact: true }),
    ).toBeVisible();
    await expect(
      page.getByText("synthetic-secret", { exact: false }),
    ).toHaveCount(0);
    await page
      .getByRole("button", { name: "管理 shared/npm-token 的标签" })
      .click();
    await dialog.getByRole("checkbox", { name: "production" }).check();
    await dialog.getByRole("button", { name: "保存", exact: true }).click();
    await expect(page.getByRole("table").getByText("production")).toBeVisible();
    await page.getByRole("button", { name: "更新", exact: true }).click();
    await expect(dialog.getByLabel("密钥值")).toHaveValue("");
    await dialog.getByLabel("密钥值").fill("synthetic-rotated-value");
    await dialog.getByRole("button", { name: "加密保存新版本" }).click();
    await expect(page.getByText("v2", { exact: true })).toBeVisible();
    await page
      .getByRole("button", { name: "shared/npm-token 版本记录" })
      .click();
    await expect(dialog.getByText("v1", { exact: true })).toBeVisible();
    await dialog.getByLabel("有效期").first().fill("2027-01-01T12:00");
    const expiry = page.waitForResponse(
      (r) => r.request().method() === "PATCH" && r.url().includes("/versions/"),
    );
    await dialog.getByRole("button", { name: "保存有效期" }).first().click();
    expect((await expiry).status()).toBe(200);
    await closeDialog();
    await page
      .getByRole("button", { name: "使用 shared/npm-token", exact: true })
      .click();
    await expect(
      dialog.getByText("cv://ws_default/shared/npm-token", { exact: true }),
    ).toBeVisible();
    await closeDialog();
  });
  await test.step("tag OR policy preview, immutable revisions and referenced-tag protection", async () => {
    await page.getByRole("link", { name: "授权规则", exact: true }).click();
    await page.getByRole("button", { name: "创建规则", exact: true }).click();
    await dialog.getByLabel("规则名称").fill("publish");
    await dialog.getByRole("button", { name: "按 Tag · 任意匹配" }).click();
    await dialog.getByRole("checkbox", { name: "production" }).check();
    await expect(dialog.getByText("当前覆盖 1 个 Key")).toBeVisible();
    await dialog.getByLabel("组织 / Owner ID").fill("12345");
    await dialog.getByLabel("仓库 ID（可选）").fill("67890");
    await dialog
      .getByLabel("工作流文件（可选）")
      .fill(".github/workflows/publish.yml");
    await dialog.getByRole("button", { name: "保存", exact: true }).click();
    await expect(page.getByRole("heading", { name: "publish" })).toBeVisible();
    await page.getByRole("button", { name: "编辑", exact: true }).click();
    await dialog.getByRole("button", { name: "保存", exact: true }).click();
    await expect(page.getByText("v2", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "版本", exact: true }).click();
    await expect(
      dialog.getByRole("heading", { name: "v1", exact: true }),
    ).toBeVisible();
    await closeDialog();
    await page.getByRole("link", { name: "标签", exact: true }).click();
    await page.getByRole("button", { name: "删除标签 production" }).click();
    await expect(page.getByRole("alert")).toBeVisible();
    await expect(
      page.getByRole("heading", { name: "production" }),
    ).toBeVisible();
  });
  await test.step("sensitive settings never echo and stale pages cannot overwrite changes", async () => {
    await page.getByRole("link", { name: "系统设置", exact: true }).click();
    await expect(page.getByLabel("提前提醒天数")).toHaveValue("7, 3, 1");
    const stale = await context.newPage();
    await stale.goto("/#settings");
    await expect(stale.getByLabel("提前提醒天数")).toHaveValue("7, 3, 1");
    await page.getByLabel("OAuth Client Secret 操作").selectOption("replace");
    await page
      .getByLabel("OAuth Client Secret 新值")
      .fill("synthetic-oauth-credential");
    await page.getByLabel("提前提醒天数").fill("10, 2");
    await page.getByRole("button", { name: "保存系统设置" }).click();
    await expect(page.getByLabel("OAuth Client Secret 操作")).toHaveValue(
      "keep",
    );
    await expect(page.getByLabel("OAuth Client Secret 新值")).toHaveCount(0);
    const config = await context.request.get("/v1/admin/settings");
    expect(await config.text()).not.toContain("synthetic-oauth-credential");
    expect((await config.json()).github_secret_configured).toBe(true);
    await stale.getByLabel("提前提醒天数").fill("5");
    await stale.getByRole("button", { name: "保存系统设置" }).click();
    await expect(stale.getByRole("alert")).toContainText("settings changed");
    await stale.close();
    await page.reload();
    await expect(page.getByLabel("提前提醒天数")).toHaveValue("10, 2");
    await page.getByRole("button", { name: "保存系统设置" }).click();
    await expect(page.getByLabel("提前提醒天数")).toHaveValue("10, 2");
    expect(
      (await (await context.request.get("/v1/admin/settings")).json())
        .github_secret_configured,
    ).toBe(true);
  });
  await test.step("one-time token, HTTP administration and immediate revocation", async () => {
    await page.getByRole("link", { name: "CLI 令牌", exact: true }).click();
    await page.getByRole("button", { name: "创建令牌", exact: true }).click();
    await dialog.getByLabel("名称", { exact: true }).fill("E2E laptop");
    const creating = page.waitForResponse(
      (r) =>
        r.url().endsWith("/v1/admin/tokens") && r.request().method() === "POST",
    );
    await dialog.getByRole("button", { name: "保存", exact: true }).click();
    const { token } = await (await creating).json();
    await expect(
      dialog.getByRole("heading", { name: "令牌已创建" }),
    ).toBeVisible();
    const headers = { Authorization: `Bearer ${token}` };
    expect(
      (await context.request.get("/v1/admin/workspaces", { headers })).status(),
    ).toBe(200);
    await dialog.getByRole("button", { name: "已保存，关闭" }).click();
    await expect(page.getByText(token, { exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "撤销", exact: true }).click();
    await expect(page.getByText("已撤销", { exact: true })).toBeVisible();
    expect(
      (await context.request.get("/v1/admin/workspaces", { headers })).status(),
    ).toBe(401);
  });
  await test.step("audit export, notification state, mobile navigation and logout", async () => {
    await page.getByRole("link", { name: "审计日志", exact: true }).click();
    await expect(
      page.getByText("key.version_created", { exact: true }).first(),
    ).toBeVisible();
    const downloading = page.waitForEvent("download");
    await page.getByRole("button", { name: "导出 JSON" }).click();
    expect((await downloading).suggestedFilename()).toBe("civault-audit.json");
    await page.getByRole("link", { name: "通知记录", exact: true }).click();
    await expect(page.getByText(/邮件通知未启用/)).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.getByRole("button", { name: "导航菜单" }).click();
    await page.getByRole("link", { name: "密钥", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "密钥", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= innerWidth,
      ),
    ).toBe(true);
    await page.screenshot({ path: "test-results/mobile.png", fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.screenshot({ path: "test-results/console.png", fullPage: true });
    await page.getByRole("button", { name: "退出登录" }).click();
    await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
    expect((await context.request.get("/v1/auth/me")).status()).toBe(401);
    expect(errors).toEqual([]);
  });
});
