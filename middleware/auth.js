const jwt = require("jsonwebtoken")
const BlackList = require("../models/BlackList")

const verifyToken = async(req, res, next)=> {
    const token = req.body.token || req.query.token || req.headers['authorization']
  
    if(!token) {
        return res.status(401).json({
            success : false,
            message : "Token is required for authentication"
        })
    }

    try {

        const bearer = token.split(' ')
        const bearerToken = bearer[1]

        const blackList = await BlackList.findOne({ token : bearerToken })
        if(blackList) {
            return res.status(401).json({
                success : false,
                message : "Token has been expired, Please login again !"
            })
        }

        const decodeData = jwt.verify(bearerToken, process.env.ACCESS_TOKEN_SECRET)
        req.user = decodeData;

    } catch (error) {
        
        return res.status(401).json({
            success : false,
            message : "Token not valid",
            error : error.message
        })
    }

    return next()
}

module.exports = verifyToken