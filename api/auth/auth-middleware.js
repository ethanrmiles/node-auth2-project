const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  const MESSAGE_401 = 'You must be logged in to access this API';

  jwt.verify(token, JWT_SECRET, async (err, decodedToken) => {
    if(err) {
      console.log('Error:', err)
      next({ status: 401, message: MESSAGE_401 });
      return;
    }

    const user = await User.findById(decodedToken.subject);
    if(decodedToken.iat < user.logged_out_time) {
      next({ status: 401, message: MESSAGE_401 });
      return;
    }

    req.decodedJwt = decodedToken;
    console.log('decoded token:', req.decodedJwt);
    next();
  })
}

function only(...roles) {
  return (req, res, next) => {
    if(roles.includes(req.decodedJwt.role)) {
      next();
    } else {
      next({ status: 403, message: 'You are not authorized to access this API' });
    }
  }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
