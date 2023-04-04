const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const jwt=require("jsonwebtoken")
const userModel=require("../users/users-model")

router.post("/register", rolAdiGecerlimi, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
    try {
      let model={
        username:req.body.username,
        password:req.body.password,
        role_name:req.body.role_name
      }
      let registeredUser=await userModel.ekle(model);
      res.status(201).json(registeredUser);

    } catch (error) {
      next(error)
    }

});


router.post("/login", usernameVarmi, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
    try {
        //req.session.user_id=req.existUser.user_id;
        const token=generateToken(req.user) 
        res.status(200).json({
          message:`${req.user.username} geri geldi!`,
          token:token
        })
    } catch (error) {
      next(error)
    }
});

function generateToken(user){
  const payload={
    subject:user.user_id,
    username:user.username,
    role_name:user.role_name
  }
  const secret=JWT_SECRET;

  const option={
    expiresIn:"1d"
  }

  return jwt.sign(payload, secret, option)
}

module.exports = router;
