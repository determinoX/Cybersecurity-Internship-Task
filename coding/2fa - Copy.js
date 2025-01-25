"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const config_1 = __importDefault(require("config"));
const basket_1 = require("../models/basket");
const user_1 = require("../models/user");
const challengeUtils = require("../lib/challengeUtils");
const utils = require("../lib/utils");
const datacache_1 = require("../data/datacache");
const security = require('../lib/insecurity');
const otplib = require('otplib');

// Configure OTP options for time window tolerance
otplib.authenticator.options = { window: 1 };

// Utility function to handle errors uniformly
function handleError(res, message = 'Unauthorized') {
    res.status(401).json({ error: message });
}

async function verify(req, res) {
    const { tmpToken, totpToken } = req.body;
    try {
        const { userId, type } = security.verify(tmpToken) && security.decode(tmpToken);
        if (type !== 'password_valid_needs_second_factor_token') {
            return handleError(res, 'Invalid token type');
        }

        const user = await user_1.UserModel.findByPk(userId);
        if (!user) {
            return handleError(res, 'No such user found!');
        }

        const isValid = otplib.authenticator.check(totpToken, user.totpSecret);
        if (!isValid) return res.status(401).send();

        challengeUtils.solveIf(datacache_1.challenges.twoFactorAuthUnsafeSecretStorageChallenge, () => user.email === 'wurstbrot@' + config_1.default.get('application.domain'));

        const [basket] = await basket_1.BasketModel.findOrCreate({ where: { UserId: userId } });
        const plainUser = utils.queryResultToJson(user);

        // Attach original basket ID to plain user data for later use
        plainUser.bid = basket.id;

        const token = security.authorize(plainUser);
        security.authenticatedUsers.put(token, plainUser);

        res.json({ authentication: { token, bid: basket.id, umail: user.email } });
    } catch (error) {
        handleError(res);
    }
}

async function status(req, res) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) return handleError(res, 'You need to be logged in to see this');

        const { data: user } = data;
        if (!user.totpSecret) {
            const secret = otplib.authenticator.generateSecret();
            const setupToken = security.authorize({
                secret,
                type: 'totp_setup_secret'
            });

            res.json({ setup: false, secret, email: user.email, setupToken });
        } else {
            res.json({ setup: true });
        }
    } catch (error) {
        handleError(res);
    }
}

async function setup(req, res) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) return handleError(res, 'Need to login before setting up 2FA');

        const { data: user } = data;
        const { password, setupToken, initialToken } = req.body;

        if (user.password !== security.hash(password)) return handleError(res, 'Password doesn’t match stored password');

        if (user.totpSecret) return handleError(res, 'User has 2FA already setup');

        const { secret, type } = security.verify(setupToken) && security.decode(setupToken);
        if (type !== 'totp_setup_secret') return handleError(res, 'SetupToken is of wrong type');

        if (!otplib.authenticator.check(initialToken, secret)) return handleError(res, 'Initial token doesn’t match the secret from the setupToken');

        // Update db model and cached object
        const userModel = await user_1.UserModel.findByPk(user.id);
        if (!userModel) return handleError(res, 'No such user found!');

        userModel.totpSecret = secret;
        await userModel.save();
        security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(userModel));

        res.status(200).send();
    } catch (error) {
        handleError(res);
    }
}

async function disable(req, res) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) return handleError(res, 'Need to login before setting up 2FA');

        const { data: user } = data;
        const { password } = req.body;

        if (user.password !== security.hash(password)) return handleError(res, 'Password doesn’t match stored password');

        // Update db model and cached object
        const userModel = await user_1.UserModel.findByPk(user.id);
        if (!userModel) return handleError(res, 'No such user found!');

        userModel.totpSecret = '';
        await userModel.save();
        security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(userModel));

        res.status(200).send();
    } catch (error) {
        handleError(res);
    }
}

module.exports.disable = () => disable;
module.exports.verify = () => verify;
module.exports.status = () => status;
module.exports.setup = () => setup;

