// server/routes/existing.js - ENHANCED ERROR HANDLING
const express = require('express');
const router = express.Router();
const { fetchContractDetails, extractSolidityCode } = require('../services/blockchainService');
const securityAnalysisService = require('../services/securityAnalysisService');
const { assessAndProtectContract } = require('../services/riskAssessmentExisting');

// Risk check only - no protection deployment
router.post('/check-only', async (req, res) => {
    try {
        console.log('🔍 Risk check endpoint called');
        
        const { contractAddress } = req.body;

        if (!contractAddress) {
            return res.status(400).json({
                success: false,
                error: 'Contract address is required'
            });
        }

        console.log(`📍 Analyzing contract: ${contractAddress}`);

        // Step 1: Fetch contract details
        let contractDetails;
        try {
            contractDetails = await fetchContractDetails(contractAddress);
        } catch (fetchError) {
            console.error('❌ Contract fetch failed:', fetchError.message);
            return res.status(404).json({
                success: false,
                error: `Failed to fetch contract: ${fetchError.message}`,
                details: 'Contract may not exist or may not be verified on Etherscan'
            });
        }

        // Step 2: Extract Solidity code
        let solidityCode;
        try {
            solidityCode = extractSolidityCode(contractDetails.rawSourceCode);
            
            if (!solidityCode || solidityCode.trim() === '') {
                throw new Error('No valid Solidity code found');
            }
        } catch (extractError) {
            console.error('❌ Code extraction failed:', extractError.message);
            return res.status(400).json({
                success: false,
                error: 'Failed to extract Solidity code',
                details: extractError.message
            });
        }

        // Step 3: Perform security analysis
        let analysisResult;
        try {
            console.log('🔍 Running security analysis...');
            analysisResult = await securityAnalysisService.analyzeContract(solidityCode);
            
            if (!analysisResult.success) {
                throw new Error(analysisResult.error || 'Analysis failed');
            }
        } catch (analysisError) {
            console.error('❌ Security analysis failed:', analysisError.message);
            return res.status(500).json({
                success: false,
                error: 'Security analysis failed',
                details: analysisError.message
            });
        }

        // Step 4: Determine if protection would be deployed
        const riskThreshold = parseFloat(process.env.RISK_THRESHOLD || '7.0');
        const wouldDeploy = analysisResult.riskScore >= riskThreshold;

        console.log(`✅ Risk check complete: Score ${analysisResult.riskScore}, Threshold ${riskThreshold}`);

        res.json({
            success: true,
            contractAddress,
            securityAnalysis: {
                riskScore: analysisResult.riskScore,
                interpretation: analysisResult.interpretation,
                threshold: riskThreshold,
                wouldDeploy
            },
            vulnerabilities: analysisResult.vulnerabilities || [],
            summary: analysisResult.summary || {},
            slitherUsed: analysisResult.slitherUsed || false,
            recommendations: analysisResult.recommendations || []
        });

    } catch (error) {
        console.error('❌ Risk check error:', error);
        res.status(500).json({
            success: false,
            error: 'Risk check failed',
            details: error.message
        });
    }
});

// Complete analysis and protection pipeline
router.post('/analyze-and-deploy', async (req, res) => {
    try {
        console.log('🛡️ Complete protection pipeline started');
        
        const { contractAddress } = req.body;

        if (!contractAddress) {
            return res.status(400).json({
                success: false,
                error: 'Contract address is required'
            });
        }

        console.log(`🎯 Processing contract: ${contractAddress}`);

        // Step 1: Fetch contract details
        let contractDetails;
        try {
            contractDetails = await fetchContractDetails(contractAddress);
        } catch (fetchError) {
            console.error('❌ Contract fetch failed:', fetchError.message);
            return res.status(404).json({
                success: false,
                error: `Contract fetch failed: ${fetchError.message}`,
                details: 'Contract may not exist or not be verified'
            });
        }

        // Step 2: Extract Solidity code
        let solidityCode;
        try {
            solidityCode = extractSolidityCode(contractDetails.rawSourceCode);
            
            if (!solidityCode || solidityCode.trim() === '') {
                throw new Error('No valid Solidity code extracted');
            }
            
            console.log(`📝 Code extracted: ${solidityCode.length} characters`);
        } catch (extractError) {
            console.error('❌ Code extraction failed:', extractError.message);
            return res.status(400).json({
                success: false,
                error: 'Failed to extract contract code',
                details: extractError.message
            });
        }

        // Step 3: Security Analysis
        let analysisResult;
        try {
            console.log('🔍 Running comprehensive security analysis...');
            analysisResult = await securityAnalysisService.analyzeContract(solidityCode);
            
            if (!analysisResult.success) {
                throw new Error(analysisResult.error || 'Security analysis failed');
            }
            
            console.log(`📊 Analysis complete: Risk ${analysisResult.riskScore}, Vulns: ${analysisResult.vulnerabilities.length}`);
        } catch (analysisError) {
            console.error('❌ Security analysis error:', analysisError.message);
            return res.status(500).json({
                success: false,
                error: 'Security analysis failed',
                details: analysisError.message,
                contractAddress
            });
        }

        // Step 4: Risk Assessment & Protection Decision
        let assessmentResult;
        try {
            console.log('⚖️ Performing risk assessment...');
            assessmentResult = await assessAndProtectContract(
                contractAddress, 
                analysisResult.riskScore, 
                analysisResult
            );
            
            console.log(`⚖️ Assessment result: ${assessmentResult.action}`);
        } catch (assessmentError) {
            console.error('❌ Risk assessment failed:', assessmentError.message);
            return res.status(500).json({
                success: false,
                error: 'Risk assessment failed',
                details: assessmentError.message,
                contractAddress,
                securityAnalysis: analysisResult
            });
        }

        // Step 5: Return comprehensive results
        const response = {
            success: true,
            contractAddress,
            securityAnalysis: {
                riskScore: analysisResult.riskScore,
                interpretation: analysisResult.interpretation,
                threshold: parseFloat(process.env.RISK_THRESHOLD || '7.0'),
                vulnerabilitiesCount: analysisResult.vulnerabilities.length,
                summary: analysisResult.summary
            },
            vulnerabilities: analysisResult.vulnerabilities || [],
            assessment: assessmentResult,
            slitherUsed: analysisResult.slitherUsed || false,
            recommendations: analysisResult.recommendations || [],
            timestamp: new Date().toISOString()
        };

        console.log(`✅ Pipeline complete: ${assessmentResult.action}`);
        
        if (assessmentResult.action === 'PROTECTED') {
            console.log(`🛡️ SecurityProxy deployed: ${assessmentResult.proxyAddress}`);
        }

        res.json(response);

    } catch (error) {
        console.error('❌ Complete pipeline error:', error);
        res.status(500).json({
            success: false,
            error: 'Complete analysis flow failed',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Health check endpoint for the existing contracts service
router.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'existing-contracts',
        features: [
            'Risk assessment for deployed contracts',
            'Automatic SecurityProxy deployment',
            'Comprehensive vulnerability analysis'
        ],
        endpoints: {
            'POST /api/risk/check-only': 'Risk assessment only',
            'POST /api/risk/analyze-and-deploy': 'Full protection pipeline'
        }
    });
});

module.exports = router;