import express from 'express'

export const jsonBodyParser = express.json({
    strict: true,
})
