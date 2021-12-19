import { client } from "./index.js";
import bcrypt from "bcrypt"
import { ObjectId } from "mongodb";

async function getByUserName(username){
    return await client.db("password").collection("users").findOne({username:username})
}

async function getByUserId(id){
    return await client.db("password").collection("users").findOne({_id:ObjectId(id)})
}

async function changeUserStatus(username){
    return await client.db("password").collection("users").updateOne({username:username},{$set:{isActive:"true"}})
}

async function genPassword(password){
    const NO_OF_ROUNDS = 10
    const salt = await bcrypt.genSalt(NO_OF_ROUNDS)
    const hashedPassword = await bcrypt.hash(password, salt)
    return hashedPassword
}

async function createUser(data) {
    return await client.db("password").collection("users").insertOne(data);
}

async function updatePassword(id,password) {
    return await client.db("password").collection("users").updateOne({_id:ObjectId(id)},{$set:{password:password}});
}

async function createUrl(data){
    return await client.db("password").collection("urls").insertOne(data)
}

async function findUrl(id){
    return await client.db("password").collection("urls").findOne({shortUrl:id})
}

async function getAllUrls(user){
    return await client.db("password").collection("urls").find({username:user}).toArray()
}

async function getAllUrlsDay(data){
    return await client.db("password").collection("urls").find({username:data.user,createdAt:data.dateTime}).count()
}

async function getAllUrlsMonth(data){
    return await client.db("password").collection("urls").find({username:data.user,createdMonth:data.monthData}).count()
}


export {getByUserName,genPassword,createUser,getByUserId,updatePassword,createUrl, findUrl, getAllUrls,getAllUrlsDay,getAllUrlsMonth,changeUserStatus}