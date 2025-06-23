import express from 'express'

export const urlEncodedParser = express.urlencoded({
    extended: false,
})
