const { JWT_SECRET } = require("../secrets"); // bu secreti kullanın!
const jwt=require("jsonwebtoken")
const userModel=require("../users/users-model")
const bcrypt =require("bcryptjs")

const sinirli = async (req, res, next) => {
  /*
    Eğer Authorization header'ında bir token sağlanmamışsa:
    status: 401
    {
      "message": "Token gereklidir"
    }

    Eğer token doğrulanamıyorsa:
    status: 401
    {
      "message": "Token gecersizdir"
    }

    Alt akıştaki middlewarelar için hayatı kolaylaştırmak için kodu çözülmüş tokeni req nesnesine koyun!
  */
    try {
      const token =req.headers.authorization;
      if(token){
        jwt.verify(token, JWT_SECRET, (err, decodedJWT)=>{
          if(err){
            res.status(401).json({message:"Token gecersizdir"})
        }
      else{
        req.decodeToken=decodedJWT
          console.log(req.decodeToken)
          next();
        }
      })
    }
      else{
        res.status(401).json({message:"Token gereklidir"})
    }

    } catch (error) {
      next(error)
    }
    
    
}

const sadece = role_name => (req, res, next) => {
  
  try {
    
    if(role_name !== req.decodeToken.role_name){
      next({
        status:403,
        message:"Bu, senin için değil"
      })
    }else{
      next();
    }

  } catch (error) {
    next(error);
  }
  /*
    
	Kullanıcı, Authorization headerında, kendi payloadu içinde bu fonksiyona bağımsız değişken olarak iletilen 
	rol_adı ile eşleşen bir role_name ile bir token sağlamazsa:
    status: 403
    {
      "message": "Bu, senin için değil"
    }

    Tekrar authorize etmekten kaçınmak için kodu çözülmüş tokeni req nesnesinden çekin!
  */
}


const usernameVarmi =async (req, res, next) => {
  /*
    req.body de verilen username veritabanında yoksa
    status: 401
    {
      "message": "Geçersiz kriter"
    }
  */
    try {
      const userByUserName =await userModel.goreBul({username:req.body.username})
      const isValidLogin=userByUserName && userByUserName.length>0 && bcrypt.compareSync(req.body.password, userByUserName[0].password)
      if(!isValidLogin){
        next({
          status:401,
          message:"Geçersiz kriter"
        })
      }else{
        req.user=userByUserName[0];
        next()
      }
    
    } catch (error) {
      next(error)
    }

}


const rolAdiGecerlimi = async (req, res, next) => {
  
  //let findRoleName=await userModel.bul()
  
  let {role_name}=req.body;
  if(!role_name || role_name.trim()==""){
    role_name="student";
  }else if(role_name.trim()=="admin"){
    next({
      status:422,
      message:"Rol adı admin olamaz"
    })
  }else if(role_name.trim().length>32){
    next({
      status:422,
      message:"rol adı 32 karakterden fazla olamaz"
    })
  }
  req.body.role_name=role_name.trim();
  req.body.password=bcrypt.hashSync(req.body.password, 12)
  next();
  
  /*
    Bodydeki role_name geçerliyse, req.role_name öğesini trimleyin ve devam edin.

    Req.body'de role_name eksikse veya trimden sonra sadece boş bir string kaldıysa,
    req.role_name öğesini "student" olarak ayarlayın ve isteğin devam etmesine izin verin.

    Stringi trimledikten sonra kalan role_name 'admin' ise:
    status: 422
    {
      "message": "Rol adı admin olamaz"
    }

    Trimden sonra rol adı 32 karakterden fazlaysa:
    status: 422
    {
      "message": "rol adı 32 karakterden fazla olamaz"
    }
  */
}

module.exports = {
  sinirli,
  usernameVarmi,
  rolAdiGecerlimi,
  sadece,
}
