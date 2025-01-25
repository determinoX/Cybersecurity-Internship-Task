"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const path = require("path");
const datacache = require("../data/datacache");
const challengeUtils = require("../lib/challengeUtils");
const utils = require("../lib/utils");
const security = require('../lib/insecurity');

module.exports = function servePublicFiles() {
    return ({ params, query }, res, next) => {
        const file = params.file;
        if (!file.includes('/')) {
            verifyFile(file, res, next);
        } else {
            res.status(403);
            next(new Error('File names cannot contain forward slashes!'));
        }
    };

    function verifyFile(file, res, next) {
        if (file && isValidFileType(file)) {
            file = security.cutOffPoisonNullByte(file);
            handleChallenges(file);
            sendFile(file, res, next);
        } else {
            res.status(403);
            next(new Error('Only .md and .pdf files are allowed!'));
        }
    }

    function isValidFileType(file) {
        return utils.endsWith(file, '.md') || utils.endsWith(file, '.pdf') || file === 'incident-support.kdbx';
    }

    function handleChallenges(file) {
        // Handle challenges for different file conditions
        if (file.toLowerCase() === 'acquisitions.md') {
            challengeUtils.solveIf(datacache.challenges.directoryListingChallenge, () => true);
        }
        if (file.toLowerCase() === 'eastere.gg') {
            challengeUtils.solveIf(datacache.challenges.easterEggLevelOneChallenge, () => true);
        }
        if (file.toLowerCase() === 'package.json.bak') {
            challengeUtils.solveIf(datacache.challenges.forgottenDevBackupChallenge, () => true);
        }
        if (file.toLowerCase() === 'coupons_2013.md.bak') {
            challengeUtils.solveIf(datacache.challenges.forgottenBackupChallenge, () => true);
        }
        if (file.toLowerCase() === 'suspicious_errors.yml') {
            challengeUtils.solveIf(datacache.challenges.misplacedSignatureFileChallenge, () => true);
        }
        if (isPoisonNullByteExploit(file)) {
            challengeUtils.solveIf(datacache.challenges.nullByteChallenge, () => true);
        }
    }

    function isPoisonNullByteExploit(file) {
        return [
            'encrypt.pyc', 
            'eastere.gg', 
            'package.json.bak', 
            'coupons_2013.md.bak', 
            'suspicious_errors.yml'
        ].includes(file.toLowerCase());
    }

    function sendFile(file, res, next) {
        try {
            res.sendFile(path.resolve('ftp/', file));
        } catch (err) {
            res.status(500);
            next(new Error('Error serving file: ' + err.message));
        }
    }
};
