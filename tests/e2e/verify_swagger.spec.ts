import { test, expect } from "@playwright/test";

test("verify Swagger UI authorization and header injection on production", async ({ page, request }) => {
  console.log("1. Signing up a fresh workspace to obtain a real API key...");
  const signupResponse = await request.post("https://agentshield-sigma.vercel.app/v1/auth/signup", {
    data: {
      email: `test_swagger_${Math.floor(Math.random() * 100000)}@agentshield.test`,
      password: "password123",
      workspace_name: "Swagger Verification Workspace"
    }
  });
  
  expect(signupResponse.status()).toBe(200);
  const signupData = await signupResponse.json();
  const apiKey = signupData.api_key;
  console.log(`✅ Fresh Workspace created. API Key: ${apiKey.slice(0, 16)}...`);

  console.log("2. Navigating to the live Swagger UI...");
  await page.goto("https://agentshield-sigma.vercel.app/docs");
  
  // Wait for Swagger UI to load
  await page.waitForSelector(".swagger-ui");
  
  console.log("3. Verifying the 'Authorize' button is visible...");
  const authButton = page.locator("button.btn.authorize");
  await expect(authButton).toBeVisible();
  console.log("✅ 'Authorize' button is present.");

  console.log("4. Opening the Authorization modal...");
  await authButton.click();
  await page.waitForSelector(".modal-ux");

  console.log("5. Entering API Key in the X-AgentShield-API-Key field...");
  // Swagger UI labels each auth field. Let's fill the input for the X-AgentShield-API-Key scheme.
  const apiKeyInput = page.locator("form").filter({ hasText: "X-AgentShield-API-Key" }).locator("input[type='text']");
  await apiKeyInput.fill(apiKey);

  console.log("6. Clicking 'Authorize' submit button...");
  const submitAuth = page.locator("form").filter({ hasText: "X-AgentShield-API-Key" }).locator("button.authorize");
  await submitAuth.click();

  console.log("7. Closing the Authorization modal...");
  const closeButton = page.locator(".modal-ux .modal-ux-header button.close-modal");
  await closeButton.click();

  console.log("8. Finding and expanding 'GET /v1/auth/me' endpoint...");
  const opblock = page.locator(".opblock").filter({ hasText: "/v1/auth/me" });
  const authMeHeader = opblock.locator(".opblock-summary-path");
  await authMeHeader.click();

  console.log("9. Clicking 'Try it out'...");
  const tryItOutButton = opblock.getByRole("button", { name: /try it out/i });
  await tryItOutButton.click();

  console.log("10. Clicking 'Execute'...");
  const executeButton = opblock.getByRole("button", { name: /execute/i });
  await executeButton.click();

  console.log("11. Waiting for server response block to render...");
  const liveResponseTable = opblock.locator(".live-responses-table");
  await expect(liveResponseTable).toBeVisible({ timeout: 15000 });

  const responseStatus = liveResponseTable.locator(".response .response-col_status");
  await expect(responseStatus).toContainText("200");
  console.log("✅ API call executed successfully. Status: 200 OK");

  console.log("12. Extracting and validating response JSON...");
  const responseBody = liveResponseTable.locator(".response-col_description pre").first();
  const responseText = await responseBody.innerText();
  console.log("Response JSON:\n", responseText);
  
  const responseJson = JSON.parse(responseText);
  expect(responseJson.workspace_name).toBe("Swagger Verification Workspace");
  expect(responseJson.status).toBe("active");
  console.log("✅ Response payload verified.");

  console.log("13. Extracting and validating the generated cURL command...");
  const curlBlock = opblock.locator("pre.curl");
  const curlText = await curlBlock.innerText();
  console.log("Generated cURL command:\n", curlText);

  expect(curlText).toContain(`-H 'X-AgentShield-API-Key: ${apiKey}'`);
  console.log("✅ cURL contains the correct injected header!");

  // Save a screenshot to document verification success
  const screenshotPath = "/Users/lol/.gemini/antigravity/brain/53b8d690-2a3e-41c9-ac59-94de735bae25/swagger_verification.png";
  await page.screenshot({ path: screenshotPath, fullPage: true });
  console.log(`✅ Saved E2E verification screenshot to ${screenshotPath}`);
});
