using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.AccessControl;
using System.Threading.Tasks;

namespace JwtIdentityMvc.Controllers
{
    public class Response
    {
        public string Status { get; set; }
        public string Message { get; set; }
    }
}
