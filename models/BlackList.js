const { timeStamp } = require("console")
const mongoose = require("mongoose")
const { type } = require("os")

const blackListSchema = mongoose.Schema({
    token : {
        type : String,
        require : true
    }
}, {timeStamp : true })

module.exports = mongoose.model("BlackList", blackListSchema)

