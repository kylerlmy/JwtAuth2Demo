using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
namespace JwtAuth2.Controllers {
  [Route ("api/[controller]")]
  public class TokenController : Controller {
    private IConfiguration _config;

    public TokenController (IConfiguration config) {
      _config = config;
    }
    //AllowAnonymous attribute. This is very important, since this must be a public API, that is an API that anyone can access to get a new token after providing his credentials.
    [AllowAnonymous]
    [HttpPost]
    public IActionResult CreateToken ([FromBody] LoginModel login) {
      IActionResult response = Unauthorized ();
      var user = Authenticate (login);

      if (user != null) {
        // var tokenString = BuildToken(user);
        var tokenString = BuildTokenWithClaim (user);
        response = Ok (new { token = tokenString });
      }

      return response;
    }

    private string BuildToken (UserModel user) {
      var key = new SymmetricSecurityKey (Encoding.UTF8.GetBytes (_config["Jwt:Key"]));
      var creds = new SigningCredentials (key, SecurityAlgorithms.HmacSha256);

      var token = new JwtSecurityToken (_config["Jwt:Issuer"],
        _config["Jwt:Issuer"],
        expires : DateTime.Now.AddMinutes (30),
        signingCredentials : creds);

      return new JwtSecurityTokenHandler ().WriteToken (token);
    }

    private string BuildTokenWithClaim (UserModel user) {

      /*标准中注册的声明 (建议但不强制使用)
      iss: jwt签发者
      sub: jwt所面向的用户
      aud: 接收jwt的一方
      exp: jwt的过期时间，这个过期时间必须要大于签发时间
      nbf: 定义在什么时间之前，该jwt都是不可用的.
      iat: jwt的签发时间
      jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
      */
      var claims = new [] {
        new Claim (JwtRegisteredClaimNames.Sub, user.Name),
        new Claim (JwtRegisteredClaimNames.Email, user.Email),
        new Claim (JwtRegisteredClaimNames.Birthdate, user.Birthdate.ToString ("yyyy-MM-dd")),
        new Claim (JwtRegisteredClaimNames.Jti, Guid.NewGuid ().ToString ())
      };

      var key = new SymmetricSecurityKey (Encoding.UTF8.GetBytes (_config["Jwt:Key"]));
      var creds = new SigningCredentials (key, SecurityAlgorithms.HmacSha256);

      var token = new JwtSecurityToken (_config["Jwt:Issuer"],
        _config["Jwt:Issuer"],
        claims,
        expires : DateTime.Now.AddMinutes (30),
        signingCredentials : creds);

      return new JwtSecurityTokenHandler ().WriteToken (token);
    }

    private UserModel Authenticate (LoginModel login) {
      UserModel user = null;

      if (login.Username == "mario" && login.Password == "secret") {
        user = new UserModel { Name = "Mario Rossi", Email = "mario.rossi@domain.com" };
      }
      return user;
    }

    public class LoginModel {
      public string Username { get; set; }
      public string Password { get; set; }
    }

    private class UserModel {
      public string Name { get; set; }
      public string Email { get; set; }
      public DateTime Birthdate { get; set; }
    }
  }
}