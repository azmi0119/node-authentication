const fs = require("fs").promises;
const path  = require("path");
const jwt = require("jsonwebtoken");
const { generate } = require("randomstring");

generateAccessToken = async(user)=> {
    const token = await jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn : "1m"})
    return token;
}

generateRefreshToken = async(user)=> {
    const token = await jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : "24h"})
    return token;
}

deleteFile = async(filePath)=> {
    try {
        await fs.unlink(filePath);
        console.log('Previous profile image has been removed successfully !')
    } catch (error) {
        console.log(error)
    }
}

module.exports = {
    generateAccessToken,
    deleteFile
}