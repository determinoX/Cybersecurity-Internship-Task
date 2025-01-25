"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getVerdict = exports.retrieveChallengesWithCodeSnippet = exports.retrieveCodeSnippet = void 0;
const fs_1 = __importDefault(require("fs"));
const js_yaml_1 = __importDefault(require("js-yaml"));
const codingChallenges_1 = require("../lib/codingChallenges");
const accuracy = __importStar(require("../lib/accuracy"));
const utils = __importStar(require("../lib/utils"));
const challengeUtils = require('../lib/challengeUtils');

// Reusable error handler to avoid code duplication
const handleError = (error, res) => {
    const statusCode = error.name === 'BrokenBoundary' ? 422 : 200;
    res.status(statusCode).json({ status: 'error', error: utils.getErrorMessage(error) });
};

// Async file reading for performance optimization
const readFileAsync = (filePath) => {
    return new Promise((resolve, reject) => {
        fs_1.default.readFile(filePath, 'utf8', (err, data) => {
            if (err) reject(err);
            resolve(data);
        });
    });
};

// Refactored retrieveCodeSnippet to handle async reading of files more efficiently
const retrieveCodeSnippet = async (challengeKey) => {
    try {
        const codeChallenges = await (0, codingChallenges_1.getCodeChallenges)();
        if (codeChallenges.has(challengeKey)) {
            return codeChallenges.get(challengeKey) ?? null;
        }
        return null;
    } catch (error) {
        throw error; // Propagate error for centralized handling
    }
};
exports.retrieveCodeSnippet = retrieveCodeSnippet;

exports.serveCodeSnippet = () => async (req, res, next) => {
    try {
        const snippetData = await (0, exports.retrieveCodeSnippet)(req.params.challenge);
        if (snippetData == null) {
            res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${req.params.challenge}` });
            return;
        }
        res.status(200).json({ snippet: snippetData.snippet });
    } catch (error) {
        handleError(error, res);
    }
};

const retrieveChallengesWithCodeSnippet = async () => {
    const codeChallenges = await (0, codingChallenges_1.getCodeChallenges)();
    return [...codeChallenges.keys()];
};
exports.retrieveChallengesWithCodeSnippet = retrieveChallengesWithCodeSnippet;

exports.serveChallengesWithCodeSnippet = () => async (req, res, next) => {
    const codingChallenges = await (0, exports.retrieveChallengesWithCodeSnippet)();
    res.json({ challenges: codingChallenges });
};

// Refactored getVerdict with better validation logic
const getVerdict = (vulnLines, neutralLines, selectedLines) => {
    if (!selectedLines || vulnLines.length > selectedLines.length) {
        return false;
    }

    // Ensure that all vulnLines are present in selectedLines
    if (!vulnLines.every(line => selectedLines.includes(line))) {
        return false;
    }

    const allowedLines = [...vulnLines, ...neutralLines];
    const invalidLines = selectedLines.filter(line => !allowedLines.includes(line));

    return invalidLines.length === 0;
};
exports.getVerdict = getVerdict;

exports.checkVulnLines = () => async (req, res, next) => {
    const key = req.body.key;
    let snippetData;
    try {
        snippetData = await (0, exports.retrieveCodeSnippet)(key);
        if (snippetData == null) {
            res.status(404).json({ status: 'error', error: `No code challenge for challenge key: ${key}` });
            return;
        }
    } catch (error) {
        handleError(error, res);
        return;
    }

    const { vulnLines, neutralLines } = snippetData;
    const selectedLines = req.body.selectedLines;
    const verdict = (0, exports.getVerdict)(vulnLines, neutralLines, selectedLines);

    let hint;
    const fixFilePath = './data/static/codefixes/' + key + '.info.yml';
    if (fs_1.default.existsSync(fixFilePath)) {
        const codingChallengeInfos = js_yaml_1.default.load(await readFileAsync(fixFilePath));
        if (codingChallengeInfos?.hints) {
            const attempts = accuracy.getFindItAttempts(key);
            if (attempts > codingChallengeInfos.hints.length) {
                hint = vulnLines.length === 1
                    ? res.__('Line {{vulnLine}} is responsible for this vulnerability or security flaw. Select it and submit to proceed.', { vulnLine: vulnLines[0].toString() })
                    : res.__('Lines {{vulnLines}} are responsible for this vulnerability or security flaw. Select them and submit to proceed.', { vulnLines: vulnLines.toString() });
            } else {
                const nextHint = codingChallengeInfos.hints[attempts - 1]; // -1 prevents after first attempt
                if (nextHint) hint = res.__(nextHint);
            }
        }
    }

    if (verdict) {
        await challengeUtils.solveFindIt(key);
        res.status(200).json({ verdict: true });
    } else {
        accuracy.storeFindItVerdict(key, false);
        res.status(200).json({ verdict: false, hint });
    }
};
