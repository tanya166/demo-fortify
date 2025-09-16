// server/routes/uploadAndDeploy.js - ENHANCED ERROR HANDLING
const express = require('express');
const router = express.Router();
const securityAnalysisService = require('../services/securityAnalysisService');
const compilationService = require('../services/compilationService');
const deploymentService = require('../services/deploymentService');

// Security analysis only - no deployment
router.post('/check-only', async (req, res) => {
    try {
        console.log('🔍 Security check endpoint called');
        
        const { code } = req.body;

        if (!code || code.trim() === '') {
            return res.status(400).json({
                success: false,
                error: 'Solidity code is required'
            });
        }

        console.log(`📝 Analyzing ${code.length} characters of code...`);

        // Perform security analysis
        let analysisResult;
        try {
            analysisResult = await securityAnalysisService.analyzeContract(code);
            
            if (!analysisResult.success) {
                throw new Error(analysisResult.error || 'Security analysis failed');
            }
        } catch (analysisError) {
            console.error('❌ Security analysis failed:', analysisError.message);
            return res.status(500).json({
                success: false,
                error: 'Security analysis failed',
                details: analysisError.message
            });
        }

        // Determine deployment status based on risk score
        const riskThreshold = 50; // Threshold for new contract deployment
        let deploymentStatus = 'ALLOWED';
        let deploymentAllowed = true;
        let message = 'Contract passed security analysis';

        if (analysisResult.riskScore >= 70) {
            deploymentStatus = 'BLOCKED';
            deploymentAllowed = false;
            message = 'CRITICAL security issues detected - deployment blocked';
        } else if (analysisResult.riskScore >= riskThreshold) {
            deploymentStatus = 'WARNING';
            deploymentAllowed = false;
            message = 'HIGH risk detected - deployment blocked for safety';
        } else if (analysisResult.riskScore >= 25) {
            deploymentStatus = 'WARNING';
            deploymentAllowed = true;
            message = 'Moderate risk detected - deployment allowed with warnings';
        }

        console.log(`📊 Analysis complete: ${analysisResult.riskScore} risk, ${deploymentStatus}`);

        res.json({
            success: true,
            riskScore: analysisResult.riskScore,
            interpretation: analysisResult.interpretation,
            deploymentStatus,
            deploymentAllowed,
            message,
            vulnerabilities: analysisResult.vulnerabilities || [],
            summary: analysisResult.summary || {},
            slitherUsed: analysisResult.slitherUsed || false,
            recommendations: analysisResult.recommendations || []
        });

    } catch (error) {
        console.error('❌ Security check error:', error);
        res.status(500).json({
            success: false,
            error: 'Security analysis failed',
            details: error.message
        });
    }
});

// Complete analysis, compilation and deployment pipeline
router.post('/analyze-and-deploy', async (req, res) => {
    try {
        console.log('🚀 Complete deployment pipeline started');
        
        const { code, contractName = 'MyContract', constructorArgs = [] } = req.body;

        if (!code || code.trim() === '') {
            return res.status(400).json({
                success: false,
                error: 'Solidity code is required'
            });
        }

        console.log(`🎯 Processing deployment for: ${contractName}`);

        // Step 1: Security Analysis
        let analysisResult;
        try {
            console.log('🔍 Step 1: Security Analysis...');
            analysisResult = await securityAnalysisService.analyzeContract(code);
            
            if (!analysisResult.success) {
                throw new Error(analysisResult.error || 'Security analysis failed');
            }
            
            console.log(`📊 Security analysis: ${analysisResult.riskScore} risk, ${analysisResult.vulnerabilities.length} vulns`);
        } catch (analysisError) {
            console.error('❌ Security analysis failed:', analysisError.message);
            return res.status(500).json({
                success: false,
                error: 'Security analysis failed',
                details: analysisError.message
            });
        }

        // Step 2: Risk Assessment & Deployment Decision
        const riskThreshold = 50; // Threshold for new contracts
        
        if (analysisResult.riskScore >= riskThreshold) {
            console.log(`🚨 Deployment BLOCKED: Risk ${analysisResult.riskScore} >= ${riskThreshold}`);
            
            const blockReasons = [];
            const criticalVulns = analysisResult.vulnerabilities.filter(v => v.severity === 'Critical');
            const highVulns = analysisResult.vulnerabilities.filter(v => v.severity === 'High');
            
            if (criticalVulns.length > 0) {
                blockReasons.push(`${criticalVulns.length} CRITICAL vulnerabilities detected`);
            }
            if (highVulns.length > 0) {
                blockReasons.push(`${highVulns.length} HIGH-severity vulnerabilities detected`);
            }
            if (analysisResult.riskScore >= 70) {
                blockReasons.push('Risk score exceeds critical threshold (70)');
            } else {
                blockReasons.push('Risk score exceeds deployment threshold (50)');
            }

            return res.status(403).json({
                success: false,
                error: 'Deployment blocked due to security risks',
                riskScore: analysisResult.riskScore,
                interpretation: analysisResult.interpretation,
                threshold: riskThreshold,
                blockReasons,
                vulnerabilities: analysisResult.vulnerabilities,
                summary: analysisResult.summary
            });
        }

        console.log(`✅ Security check passed: ${analysisResult.riskScore} < ${riskThreshold}`);

        // Step 3: Compilation
        let compilationResult;
        try {
            console.log('🔧 Step 2: Compiling contract...');
            compilationResult = await compilationService.compileContract(code, `${contractName}.sol`);
            
            if (!compilationResult.success) {
                throw new Error(compilationResult.error || 'Compilation failed');
            }
            
            console.log(`✅ Compilation successful: ${compilationResult.contractName}`);
        } catch (compilationError) {
            console.error('❌ Compilation failed:', compilationError.message);
            return res.status(400).json({
                success: false,
                error: 'Contract compilation failed',
                details: compilationError.message,
                security: analysisResult // Include security analysis even if compilation fails
            });
        }

        // Step 4: Deployment
        let deploymentResult;
        try {
            console.log('🚀 Step 3: Deploying to blockchain...');
            deploymentResult = await deploymentService.deployContract({
                abi: compilationResult.abi,
                bytecode: compilationResult.bytecode,
                contractName: compilationResult.contractName,
                constructorArgs
            });
            
            if (!deploymentResult.success) {
                throw new Error(deploymentResult.error || 'Deployment failed');
            }
            
            console.log(`🎉 Deployment successful: ${deploymentResult.contractAddress}`);
        } catch (deploymentError) {
            console.error('❌ Deployment failed:', deploymentError.message);
            return res.status(500).json({
                success: false,
                error: 'Contract deployment failed',
                details: deploymentError.message,
                security: analysisResult,
                compilation: compilationResult
            });
        }

        // Step 5: Success Response
        const response = {
            success: true,
            message: 'Contract successfully analyzed, compiled, and deployed',
            security: {
                riskScore: analysisResult.riskScore,
                interpretation: analysisResult.interpretation,
                vulnerabilitiesCount: analysisResult.vulnerabilities.length,
                slitherUsed: analysisResult.slitherUsed,
                warnings: analysisResult.vulnerabilities
                    .filter(v => v.severity === 'Medium' || v.severity === 'Low')
                    .map(v => `${v.severity}: ${v.type}`)
            },
            compilation: {
                contractName: compilationResult.contractName,
                warningsCount: compilationResult.warnings?.length || 0,
                warnings: compilationResult.warnings
            },
            deployment: {
                contractAddress: deploymentResult.contractAddress,
                transactionHash: deploymentResult.transactionHash,
                networkName: deploymentResult.networkName,
                explorerUrl: deploymentResult.explorerUrl,
                gasUsed: deploymentResult.gasUsed,
                deploymentCost: deploymentResult.deploymentCost
            },
            timestamp: new Date().toISOString()
        };

        console.log(`🎉 Complete pipeline successful!`);
        res.json(response);

    } catch (error) {
        console.error('❌ Deployment pipeline error:', error);
        res.status(500).json({
            success: false,
            error: 'Deployment pipeline failed',
            details: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Force deployment (emergency override)
router.post('/force-deploy', async (req, res) => {
    try {
        console.log('⚠️ FORCE DEPLOYMENT requested');
        
        const { code, contractName = 'ForceDeployedContract', constructorArgs = [], override = false } = req.body;

        if (!override) {
            return res.status(403).json({
                success: false,
                error: 'Force deployment requires explicit override confirmation',
                message: 'Add "override": true to bypass security checks'
            });
        }

        if (!code || code.trim() === '') {
            return res.status(400).json({
                success: false,
                error: 'Solidity code is required'
            });
        }

        console.log('⚠️ BYPASSING security checks - force deployment mode');

        // Quick compilation check
        let compilationResult;
        try {
            compilationResult = await compilationService.compileContract(code, `${contractName}.sol`);
            
            if (!compilationResult.success) {
                throw new Error(compilationResult.error);
            }
        } catch (error) {
            return res.status(400).json({
                success: false,
                error: 'Compilation failed - cannot force deploy broken code',
                details: error.message
            });
        }

        // Deploy without security checks
        let deploymentResult;
        try {
            deploymentResult = await deploymentService.deployContract({
                abi: compilationResult.abi,
                bytecode: compilationResult.bytecode,
                contractName: compilationResult.contractName,
                constructorArgs
            });
            
            if (!deploymentResult.success) {
                throw new Error(deploymentResult.error);
            }
        } catch (error) {
            return res.status(500).json({
                success: false,
                error: 'Force deployment failed',
                details: error.message
            });
        }

        console.log(`⚠️ FORCE DEPLOYMENT successful: ${deploymentResult.contractAddress}`);

        res.json({
            success: true,
            warning: 'CONTRACT DEPLOYED WITHOUT SECURITY ANALYSIS',
            message: 'Force deployment completed - use at your own risk',
            deployment: deploymentResult,
            compilation: {
                contractName: compilationResult.contractName,
                warnings: compilationResult.warnings
            },
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('❌ Force deployment error:', error);
        res.status(500).json({
            success: false,
            error: 'Force deployment failed',
            details: error.message
        });
    }
});

// Health check for deployment service
router.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        service: 'contract-deployment',
        features: [
            'Security analysis with enhanced pattern detection',
            'Solidity compilation',
            'Ethereum deployment',
            'Force deployment override'
        ],
        endpoints: {
            'POST /api/deploy/check-only': 'Security analysis only',
            'POST /api/deploy/analyze-and-deploy': 'Complete deployment pipeline',
            'POST /api/deploy/force-deploy': 'Emergency deployment override'
        }
    });
});

module.exports = router;