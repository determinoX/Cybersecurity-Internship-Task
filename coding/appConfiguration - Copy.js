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

module.exports = function retrieveAppConfiguration() {
    return (_req, res) => {
        try {
            // Send the entire config object as JSON response
            res.json({ config: config_1.default });
        } catch (error) {
            // Handle any potential errors (though unlikely in this case)
            res.status(500).json({ error: 'Unable to retrieve app configuration' });
        }
    };
};
//# sourceMappingURL=appConfiguration.js.map
