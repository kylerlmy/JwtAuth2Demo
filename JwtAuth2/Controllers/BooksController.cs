using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace JwtAuth2.Controllers {
    [Route ("api/[controller]")]
    public class BooksController : Controller {
        [HttpGet, Authorize]
        public IEnumerable<Book> Get () {

             return GetBooksUseClaim ();
            //return GetBooks();
        }
        private Book[] GetBooks () {
            var currentUser = HttpContext.User;
            var resultBookList = new Book[] {
                new Book { Author = "Ray Bradbury", Title = "Fahrenheit 451" },
                new Book { Author = "Gabriel García Márquez", Title = "One Hundred years of Solitude" },
                new Book { Author = "George Orwell", Title = "1984" },
                new Book { Author = "Anais Nin", Title = "Delta of Venus" }
            };

            return resultBookList;
        }

        private Book[] GetBooksUseClaim () {
            var currentUser = HttpContext.User;
            int userAge = 0;
            var resultBookList = new Book[] {
                new Book { Author = "Ray Bradbury", Title = "Fahrenheit 451", AgeRestriction = false },
                new Book { Author = "Gabriel García Márquez", Title = "One Hundred years of Solitude", AgeRestriction = false },
                new Book { Author = "George Orwell", Title = "1984", AgeRestriction = false },
                new Book { Author = "Anais Nin", Title = "Delta of Venus", AgeRestriction = true }
            };

            if (currentUser.HasClaim (c => c.Type == ClaimTypes.DateOfBirth)) {
                DateTime birthDate = DateTime.Parse (currentUser.Claims.FirstOrDefault (c => c.Type == ClaimTypes.DateOfBirth).Value);
                userAge = DateTime.Today.Year - birthDate.Year;
            }

            if (userAge < 18) {
                resultBookList = resultBookList.Where (b => !b.AgeRestriction).ToArray ();
            }

            return resultBookList;
        }
    }

    public class Book {
        public string Author { get; set; }
        public string Title { get; set; }
        public bool AgeRestriction { get; set; }
    }
}