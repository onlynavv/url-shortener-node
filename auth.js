import jwt from "jsonwebtoken"

export const auth = (request, response, next) =>{
    try{
        const token = request.header("x-auth-token")
        jwt.verify(token, process.env.SECRET_KEY, (err,data)=>{
            request.user = data
        })
        next()
    }catch(err){
        response.status(401).send({msg:"invalid signature"})
    }
}

export const authAndVerifyUser = (request, response, next)=>{
    auth(request, response, ()=>{
        if(request.user.isActive !== "true"){
            response.status(401).send({msg:"you need to verify, verifcation has been sent to your email"})
        }
        next()
    })
}

export const authAndVerifyAdmin = (request, response, next)=>{
    auth(request, response, ()=>{
        if(request.user.isAdmin){
            next()
        }else{
            response.status(401).send({msg:"you are not allowed"})
        }
    })
}