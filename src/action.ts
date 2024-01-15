import * as core from '@actions/core';
import * as github from '@actions/github';
import fetch from 'node-fetch';
import fs from 'fs';

async function extractLinks(filename: string): Promise<string[]> {
    try {
        const fileContent = fs.readFileSync(filename, 'utf8');
        const urlRegex = /(http|https):\/\/[a-zA-Z0-9./?=_%:-]+/g;
        const urls = fileContent.match(urlRegex);
        // Exclude specific domains
        const excludedDomains = ['github.com', 'youtu.be', 'twitter.com', 'dune.com', 'rawgit.com', 'ethereum.org', 'medium.com', 'www.youtube.com', 'discord'];

        const filteredUrls = urls ? urls.filter(url => {
            return !excludedDomains.some(domain => url.includes(domain));
        }) : [];

        return Array.from(new Set(filteredUrls));
    } catch (error) {
        core.setFailed(`Error extracting links from ${filename}: ${error.message}`);
        return [];
    }
}

function base64EncodeWithoutPadding(url: string): string {
    return Buffer.from(url).toString('base64').replace(/=+$/, '');
}
async function scanAndCheckUrl(url: string, apiKey: string): Promise<any> {
    try {
        const scanResponse = await fetch(`https://www.virustotal.com/api/v3/urls`, {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        const scanResult = await scanResponse.json();

        if (scanResponse.status !== 200) {
            throw new Error(`Error scanning URL: ${scanResult.error.message}`);
        }

        const analysisId = scanResult.data.id;
        await new Promise(resolve => setTimeout(resolve, 15000));

        const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        return await analysisResponse.json();
    } catch (error) {
        throw error;
    }
}


async function checkUrlWithVirusTotal(url: string, apiKey: string): Promise<any> {
    try {
        const encodedUrl = base64EncodeWithoutPadding(url);
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        if (response.status === 404) {
            return scanAndCheckUrl(url, apiKey);
        } else if (response.status === 429) {
            throw new Error('Rate limit exceeded');
        }

        return await response.json();
    } catch (error) {
        throw error;
    }
}


async function run(): Promise<void> {
    try {
        const owner = github.context.repo.owner;
        const repo = github.context.repo.repo;
        const apiKey = core.getInput('virustotal-api-key', { required: true });
        const filename = core.getInput('filename') || 'README.md';
        const malicious_threshold = parseInt(core.getInput('malicious_threshold')) || 0;
        const suspicious_threshold = parseInt(core.getInput('suspicious_threshold')) || 0;
        const urls = await extractLinks(filename);
        let flaggedUrls: { url: string; stats: any }[] = [];
        let totalScanned = 0;
        let totalMalicious = 0;

        console.log(`Total URLs to be scanned from ${filename}: ${urls.length}`);

        for (const url of urls) {
            console.log(`Scanning URL: ${url}`);
            try {
                const result = await checkUrlWithVirusTotal(url, apiKey);
                totalScanned++;
                const analysisStats = result?.data?.attributes?.last_analysis_stats;
                if (analysisStats && (analysisStats.malicious > malicious_threshold || analysisStats.suspicious > suspicious_threshold)) {
                    flaggedUrls.push({ url, stats: analysisStats });
                    totalMalicious++;
                }

                // Wait for 30 seconds before the next request due to VirusTotal rate limit.
                await new Promise(resolve => setTimeout(resolve, 30000));
            } catch (error) {
                console.log(error);
                if (error.message === 'Rate limit exceeded') {
                    core.setFailed(`VirusTotal API rate limit exceeded. Failed to check URL: ${url}`);
                    return;
                } else {
                    core.error(`Error checking URL ${url}: ${error.message}`);
                }
            }
        }

        console.log(`Total Scanned URLs: ${totalScanned}`);
        console.log(`Total Malicious URLs: ${totalMalicious}`);

        if (flaggedUrls.length > 0) {
            console.log('Malicious URLs:');
            flaggedUrls.forEach(({ url, stats }) => {
                console.log(`URL: ${url} = Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}`);
            });
            core.setFailed('One or more URLs have been flagged.');
        } else {
            core.info('No harmful URLs detected.');
        }

    } catch (error) {
        core.setFailed(`Action failed: ${error.message}`);
    }
}

run();