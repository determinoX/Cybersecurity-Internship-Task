"use strict";
/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
const os = require("os");
const fs = require("fs");
const path = require("path");
const challengeUtils = require("../lib/challengeUtils");
const utils = require("../lib/utils");
const datacache = require("../data/datacache");
const libxml = require("libxmljs");
const vm = require("vm");
const unzipper = require("unzipper");

function ensureFileIsPassed({ file }, res, next) {
    if (file != null) {
        next();
    } else {
        next(new Error("No file uploaded"));
    }
}

function handleZipFileUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), ".zip")) {
        if (file?.buffer && utils.isChallengeEnabled(datacache.challenges.fileWriteChallenge)) {
            const buffer = file.buffer;
            const filename = file.originalname.toLowerCase();
            const tempFile = path.join(os.tmpdir(), filename);

            fs.open(tempFile, "w", (err, fd) => {
                if (err) {
                    return next(err);
                }

                fs.write(fd, buffer, 0, buffer.length, null, (writeErr) => {
                    if (writeErr) {
                        return next(writeErr);
                    }

                    fs.close(fd, () => {
                        fs.createReadStream(tempFile)
                            .pipe(unzipper.Parse())
                            .on("entry", (entry) => {
                                const fileName = entry.path;
                                const absolutePath = path.resolve("uploads/complaints/" + fileName);
                                challengeUtils.solveIf(datacache.challenges.fileWriteChallenge, () => {
                                    return absolutePath === path.resolve("ftp/legal.md");
                                });

                                if (absolutePath.includes(path.resolve("."))) {
                                    entry.pipe(
                                        fs.createWriteStream("uploads/complaints/" + fileName).on("error", (err) => next(err))
                                    );
                                } else {
                                    entry.autodrain();
                                }
                            })
                            .on("error", (err) => next(err));
                    });
                });
            });
        }
        res.status(204).end();
    } else {
        next();
    }
}

function checkUploadSize({ file }, res, next) {
    if (file != null) {
        challengeUtils.solveIf(datacache.challenges.uploadSizeChallenge, () => {
            return file?.size > 100000;
        });
    }
    next();
}

function checkFileType({ file }, res, next) {
    const fileType = file?.originalname.split(".").pop().toLowerCase();
    challengeUtils.solveIf(datacache.challenges.uploadTypeChallenge, () => {
        return !(["pdf", "xml", "zip"].includes(fileType));
    });
    next();
}

function handleXmlUpload({ file }, res, next) {
    if (utils.endsWith(file?.originalname.toLowerCase(), ".xml")) {
        challengeUtils.solveIf(datacache.challenges.deprecatedInterfaceChallenge, () => true);

        if (file?.buffer && utils.isChallengeEnabled(datacache.challenges.deprecatedInterfaceChallenge)) {
            const data = file.buffer.toString();

            try {
                const sandbox = { libxml, data };
                vm.createContext(sandbox);

                const xmlDoc = vm.runInContext(
                    "libxml.parseXml(data, { noblanks: true, noent: true, nocdata: true })",
                    sandbox,
                    { timeout: 2000 }
                );
                const xmlString = xmlDoc.toString(false);

                challengeUtils.solveIf(datacache.challenges.xxeFileDisclosureChallenge, () => {
                    return utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString);
                });

                res.status(410);
                next(new Error(`B2B customer complaints via file upload have been deprecated for security reasons: ${utils.trunc(xmlString, 400)} (${file.originalname})`));
            } catch (err) {
                if (err.message.includes("Script execution timed out")) {
                    if (challengeUtils.notSolved(datacache.challenges.xxeDosChallenge)) {
                        challengeUtils.solve(datacache.challenges.xxeDosChallenge);
                    }
                    res.status(503);
                    next(new Error("Sorry, we are temporarily not available! Please try again later."));
                } else {
                    res.status(410);
                    next(new Error(`B2B customer complaints via file upload have been deprecated for security reasons: ${err.message} (${file?.originalname})`));
                }
            }
        } else {
            res.status(410);
            next(new Error(`B2B customer complaints via file upload have been deprecated for security reasons (${file?.originalname})`));
        }
    } else {
        res.status(204).end();
    }
}

module.exports = {
    ensureFileIsPassed,
    handleZipFileUpload,
    checkUploadSize,
    checkFileType,
    handleXmlUpload,
};
