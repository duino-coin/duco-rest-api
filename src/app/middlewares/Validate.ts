import {validationResult} from 'express-validator'
import Request from "@/interfaces/Request";
import {NextFunction, Response} from "express";

export default (req: Request, res: Response, next: NextFunction) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({errors: errors.array()});
    }

    return next();
}