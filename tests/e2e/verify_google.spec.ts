import { test, expect } from "@playwright/test";

test("should load signin page and verify Google Sign-in is active", async ({ page }) => {
  // Go to the production signin page
  await page.goto("https://agentshield-sigma.vercel.app/signin");

  // Verify the Google sign-in button is present
  const googleBtn = page.locator("button.btn-google");
  await expect(googleBtn).toBeVisible();
  await expect(googleBtn).toContainText("Continue with Google");

  // Click the button
  await googleBtn.click();

  // Wait a few seconds to let any error messages or popups render
  await page.waitForTimeout(4000);

  // Get all visible text elements that might contain errors
  const pageText = await page.locator("body").innerText();
  console.log("Page text after clicking Google button:", pageText);

  // Assert that "Google sign-in is currently unavailable" is NOT present on the page
  expect(pageText).not.toContain("Google sign-in is currently unavailable");
  
  // Also check that it doesn't show general configuration error messages
  expect(pageText).not.toContain("Firebase not configured");
  
  console.log("Verification Passed: Google Sign-in is configured and active!");
});
