import Koa from "koa";
import supertest from "supertest";

import { JwksService } from "../src/lib/jwksService";
import { extractJwtToken } from "../src/lib/middleware";

beforeEach(jest.restoreAllMocks);
describe(extractJwtToken.name, () => {
  const jwksService = new JwksService(
    "https://auth.example.com/realms/test-realm"
  );

  const mockUserData = {
    email: "user@example.com",
    name: "Test User",
    preferred_username: "testuser",
  };

  const app = new Koa();
  app.use(extractJwtToken(jwksService));
  app.use((ctx) => {
    ctx.status = 200;
    ctx.body = ctx.state.user;
  });

  it("extracts token from cookie", async () => {
    const verifyTokenSpy = jest
      .spyOn(jwksService, "verifyToken")
      .mockResolvedValueOnce(mockUserData);

    const cookie = "auth_token=foobar";
    const response = await supertest(app.callback())
      .get("/")
      .set("Cookie", cookie);

    expect(verifyTokenSpy).toHaveBeenCalledWith("foobar");

    expect(response.status).toBe(200);
    expect(response.body).toMatchObject(mockUserData);
  });

  it("extracts token from Authorization header if no cookie present", async () => {
    const verifyTokenSpy = jest
      .spyOn(jwksService, "verifyToken")
      .mockResolvedValueOnce(mockUserData);

    const authHeader = "Bearer foobar";
    const response = await supertest(app.callback())
      .get("/")
      .set("Authorization", authHeader);

    expect(verifyTokenSpy).toHaveBeenCalledWith("foobar");
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject(mockUserData);
  });

  it("responds with 401 if no token is provided", async () => {
    const response = await supertest(app.callback()).get("/");
    expect(response.status).toBe(401);
  });

  it("responds with 401 if token verification fails", async () => {
    jest.spyOn(jwksService, "verifyToken").mockRejectedValueOnce("oops");

    const response = await supertest(app.callback())
      .get("/")
      .set("Authorization", "Bearer valid-token");

    expect(response.status).toBe(401);
  });
});
