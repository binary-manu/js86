js86 = (function () {

    var js86 = {};
    
    var MOD_MEM = 0;
    var MOD_MEM_DISP8 = 1;
    var MOD_MEM_DISP16 = 2;
    var MOD_MEM_REG = 3;
    var RM_DISPONLY = 6;
    
    var SEGOVERRIDE_ES = 0x26;
    var SEGOVERRIDE_CS = 0x2E;
    var SEGOVERRIDE_SS = 0x36;
    var SEGOVERRIDE_DS = 0x3E;
    
    var REP_ZERO = 0xF3;
    var REP_NOTZERO = 0xF2;
    
    var LOCK_PREFIX = 0xF0;
    
    var EXCEPTION_ENDOFSTREAM = js86.EXCEPTION_ENDOFSTREAM = "EndOfStreamException";
    var EXCEPTION_BADOPCODE = js86.EXCEPTION_BADOPCODE = "BadOpcodeException";
    var EXCEPTION_BADOPSTRUCT = js86.EXCEPTION_BADOPSTRUCT = "BadOpcodeStructureException";
    
    var throwIt = function(excType, message, extra) {
        throw { "name" : excType, "message" : message, "extra" : extra };
    };
    
    var toSigned = function(value, max) {
        if (value >= (max/2))
            value = value - max;
        return value;
    };
    
    var makeToSigned = function(max) {
        return function(value) {
            return toSigned(value, max);
        };
    };
    
    var toSigned8 = makeToSigned(256);
    var toSigned16 = makeToSigned(65536);
    
    js86.toSigned = toSigned;
    js86.toSigned8 = toSigned8;
    js86.toSigned16 = toSigned16;
    
    /**
     * <p>Tries to decode a MOD/REG/RM byte and its associated (optional)
     * displacement from the next bytes of the stream.</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>reg: the value of the REG bit field</li>
     * <li>mod: the value of the MOD bit field</li>
     * <li>rm: the value of the RM bit field</li>
     * <li>disp: the value of the displacement, as a signed value</li>
     * </ul>
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var decodeModRegRm = function(info, allowedReg, allowedMod) {
        allowedReg = allowedReg || [true, true, true, true, true, true, true, true];
        allowedMod = allowedMod || [true, true, true, true];
        var theByte = info.opcodes.getByte();
        var reg = (theByte >> 3) & 0x07;
        var disp;
        var rm = theByte & 0x07;
        var mod = (theByte >> 6) & 0x03;
        if (!allowedReg[reg] || !allowedMod[mod]) {
            throwIt(
                EXCEPTION_BADOPCODE,
                "MOD/REG/RM byte contains a value not allowed for this instruction",
                {stream : info.opcodes}
            );
        }
        disp = 0;
        if (mod === MOD_MEM_DISP8) {
            disp = toSigned8(info.opcodes.getByte());
        } else if (mod === MOD_MEM_DISP16 || (mod === MOD_MEM && rm === RM_DISPONLY)) {
            disp = info.opcodes.getByte();
            disp += info.opcodes.getByte() * 256;
            disp = toSigned16(disp);
        }
        
        info.decoded.reg = reg;
        info.decoded.mod = mod;
        info.decoded.rm = rm;
        info.decoded.disp = disp;
    };
    
    /**
     * <p>Tries to decode the rest of an instruction in the form
     * OPCODE MOD/REG/RM (disp-lo (disp-hi)?)?
     * </p>
     * <p>
     * Since this boils down to decoding the MOD/REG/RM sequence, it works
     * just like decodeModRegRm.
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     * @see decodeModRegRm
     */
    var dcModRegRm = function(info) {
        decodeModRegRm(info);
    };
    
    var dcModRegRmMemory = function(info) {
        decodeModRegRm(info, null, [true, true, true, false]);
    };
    
    /**
     * <p>Tries to decode an instruction in the form OPCODE IMM8</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>imm1: the value of the immediate, as an unsigned value</li>
     * </ul>
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var dcImm8 = function(info) {
        // Decode an instruction in the form OPCODE IMM8
        info.decoded.imm1 = info.opcodes.getByte();
    };
    
    /**
     * <p>Tries to decode an instruction in the form OPCODE IMM16</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>imm1: the value of the immediate, as an unsigned value</li>
     * </ul>
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var dcImm16 = function(info) {
        var imm = info.opcodes.getByte();
        imm += info.opcodes.getByte() * 256;
        info.decoded.imm1 = imm;
    };
    
    /**
     * <p>Tries to decode an instruction in the form OPCODE</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * Since this method parses what come after the opcode, this is actually
     * just a no-op method.
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var dcOpcode = function(info) {
        // Decode an instruction in the form OPCODE
        // Oh, it's already done :)
    };
    
    /**
     * <p>Tries to decode an instruction in the form OPCODE MOD/SEG/RM and
     * its displacement.</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>reg: the value of the REG bit field, which is actually a segment register</li>
     * <li>seg: the same as reg, but it's only present when the reg field points to a segment reister</li>
     * <li>mod: the value of the MOD bit field</li>
     * <li>rm: the value of the RM bit field</li>
     * <li>disp: the value of the displacement, as a signed value</li>
     * </ul>
     * </p>
     * <p>
     * This will throw an exception if REG fields holds an invalid encoding.
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var dcModSegRm = function(mask) {
        return function(info) {
            decodeModRegRm(info, mask.concat([false, false, false, false]));
            info.decoded.seg = info.decoded.reg;
        };
    };
    
    /**
     * <p>Tries to decode an instruction in the form OPCODE IMM16 IMM16.</p>
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>imm1: the value of the first (closest to the opcode) immediate, as an unsigned value</li>
     * <li>imm2: the value of the second (farther from the opcode) immediate, as an unsigned value</li>
     * </ul>
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var dcTwoImm = function(info) {
        var imm1, imm2;
        imm1 = info.opcodes.getByte();
        imm1 += info.opcodes.getByte() * 256;
        imm2 = info.opcodes.getByte();
        imm2 += info.opcodes.getByte() * 256;
        info.decoded.imm1 = imm1;
        info.decoded.imm2 = imm2;
    };
    
    /**
     * <p>Create a function for parsing instructions with opcodes extensions in the REG field.</p>
     * <p>
     * The only argument should be an array of 8 integer, one for each possible combination
     * of the 3-bit opcode extension, where each item can take one of this choices:
     * <ul>
     * <li>-1: this opcode extension is not assigned</li>
     * <li>0: this opcode extension have no immediate in the instruction</li>
     * <li>1: this opcode extension have a 1-byte immediate in the instruction</li>
     * <li>2: this opcode extension have a 2-byte immediate in the instruction</li>
     * </ul>
     * </p>
     * 
     * <p> The returned function will try to parse instructions as per its
     * extension specification.
     * <p>If the stream ends before the all the needed bytes can be read, decoded
     * is not modified. Otherwise the following properties are added to it:
     * <ul>
     * <li>ext: the value of the REG bit field, which is actually an opcode extension</li>
     * <li>mod: the value of the MOD bit field</li>
     * <li>rm: the value of the RM bit field</li>
     * <li>disp: the value of the displacement, as a signed value</li>
     * </ul>
     * </p>
     * 
     * <p>This function will throw an exception if it comes across an extension
     * that is deemed unsupported by the input array.
     * </p>
     * 
     * @param {Object} decoded Broken down representation of an instruction
     * @param {Stream} opcodes Byte stream from which opcodes are retrieved
     */
    var makeModExtRmDc = function(extMap) {
        var allowedReg = [];
        for (i = 0; i < extMap.length; i++) {
            allowedReg.push(extMap[i] >= 0);
        }
        return function(info) {
            var ext, extFlag, imm, scale;
            decodeModRegRm(info, allowedReg);
            ext = info.decoded.reg;
            info.decoded.ext = ext;
            delete info.decoded.reg; // There is no reg in this instruction
            extFlag = extMap[ext];
            imm = 0;
            scale = 1;
            for (; extFlag > 0; extFlag--) {
                imm += info.opcodes.getByte() * scale;
                scale *= 256;
            }
            if (scale > 1) {
                info.decoded.imm1 = imm;
            }
        };
    };
    
    var dcPrefix = function(info) {
        info.decoded.prefixes = info.decoded.prefixes || [];
        info.decoded.prefixes.push(info.decoded.opcode);
        delete info.opcode;
        info.disassemble(info);
    };
    
    var opcodeToDecodingClass = [
        // 00
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcOpcode,
        dcOpcode,
        // 08
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcOpcode,
        undefined,
        // 10
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcOpcode,
        dcOpcode,
        // 18
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcOpcode,
        dcOpcode,
        // 20
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcPrefix,       // Segment Override
        dcOpcode,
        // 28
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcPrefix,       // Segment override
        dcOpcode,
        // 30
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcPrefix,       // Segment override
        dcOpcode,
        // 38
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcImm8,
        dcImm16,
        dcPrefix,       // Segment override,
        dcOpcode,
        // 40
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // 48
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // 50
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // 58
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // 60
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        // 68
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        // 70
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        // 78
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        // 80
        makeModExtRmDc([1,1,1,1,1,1,1,1]),
        makeModExtRmDc([2,2,2,2,2,2,2,2]),
        makeModExtRmDc([1,-1,1,1,-1,1,-1,1]),
        makeModExtRmDc([1,-1,1,1,-1,1,-1,1]),
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        // 88
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModRegRm,
        dcModSegRm([true, true, true, true]),
        dcModRegRmMemory,
        dcModSegRm([true, false, true, true]),      // this is for MOV SEG, MEM/REG, which should not accept CS as a target
        makeModExtRmDc([0,-1,-1,-1,-1,-1,-1,-1]),
        // 90
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // 98
        dcOpcode,
        dcOpcode,
        dcTwoImm,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // A0
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // A8
        dcImm8,
        dcImm16,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // B0
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        // B8
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        dcImm16,
        // C0
        undefined,
        undefined,
        dcImm16,
        dcOpcode,
        dcModRegRmMemory,
        dcModRegRmMemory,
        makeModExtRmDc([1,-1,-1,-1,-1,-1,-1,-1]),
        makeModExtRmDc([2,-1,-1,-1,-1,-1,-1,-1]),
        // C8
        undefined,
        undefined,
        dcImm16,
        dcOpcode,
        dcOpcode,
        dcImm8,
        dcOpcode,
        dcOpcode,
        // D0
        makeModExtRmDc([0,0,0,0,0,0,-1,0]),
        makeModExtRmDc([0,0,0,0,0,0,-1,0]),
        makeModExtRmDc([0,0,0,0,0,0,-1,0]),
        makeModExtRmDc([0,0,0,0,0,0,-1,0]),
        dcImm8,
        dcImm8,
        undefined,
        dcOpcode,
        // D8 (escape instructions, treated as undefined)
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        // E0
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        dcImm8,
        // E8
        dcImm16,
        dcImm16,
        dcTwoImm,
        dcImm8,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        // F0
        dcPrefix, // LOCK prefix
        undefined,
        dcPrefix, // REPNZ
        dcPrefix, // REPZ
        dcOpcode,
        dcOpcode,
        makeModExtRmDc([1,-1,0,0,0,0,0,0]),
        makeModExtRmDc([2,-1,0,0,0,0,0,0]),
        // F8
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        dcOpcode,
        makeModExtRmDc([0,0,-1,-1,-1,-1,-1,-1]),
        makeModExtRmDc([0,0,0,0,0,0,0,-1])
    ];
    
    var makePutbackByteStream = function(delegate) {
        var theBytes = []
        var nBytes = 0;
        
        return {
            "isEof" : function() {
                return nBytes <= 0 && delegate.isEof();
            },
            
            "getPosition" : function() {
                return delegate.getPosition() - nBytes;
            },
            
            "getByte" : function() {
                var newByte;
                if (nBytes > 0) {
                    return theBytes[--nBytes];
                } else {
                    newByte = delegate.getByte();
                    theBytes.unshift(newByte);
                    return newByte;
                }
            },
            
            "putback" : function() {
                nBytes = theBytes.length;
            },
            
            "discard" : function() {
                if (nBytes >= theBytes.length) {
                    theBytes = [];
                } else {
                    theBytes.splice(nBytes, theBytes.length - nBytes);
                }
            }
        };
    };
    
    var makeByteStreamFromString = function(string) {
        var position = 0;
        
        var getByte = function() {
            if (position >= string.length) {
                throwIt(EXCEPTION_ENDOFSTREAM, "Unexpected end of opcode stream");
            }
            return string.charCodeAt(position++);
        };
        
        var isEof = function() {
            return position >= string.length;
        };
        
        var getPosition = function() {
            return position;
        };
        
        return makePutbackByteStream({
            getByte : getByte,
            isEof : isEof,
            getPosition : getPosition
        });
    };
    js86.makeByteStreamFromString = makeByteStreamFromString;
    
    var makeByteStreamFromHexString = function(string) {
        var matcher = new RegExp("\\s*([0-9A-F])([0-9A-F])\\s*", "gi");
        var result = null;
        var byteString = "";
        while (true) {
            result = matcher.exec(string);
            if (!result) {
                break;
            }
            byteString += String.fromCharCode(parseInt("0x" + result));
        }
        return makeByteStreamFromString(byteString);
    };
    js86.makeByteStreamFromHexString = makeByteStreamFromHexString;

    var makeIntelSyntaxFormatter = function(params) {
        params = params || {};
        
        var state = {
            org : (typeof(params.org) === "number" && isFinite(params.org) && params.org >= 0) ? params.org : 0     // Initial disassembly address
        };
        
        var toGPRegName = function() {
            var regMap = [
                // One row for each size, the first is unused so that the
                // index is equal to the size of the register in bytes
                [],
                ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"],   // 8 bits
                ["ax", "bx", "cx", "dx", "sp", "bp", "si", "di"]    // 16 bits
            ];
            
            return function(reg, size) {
                var row = regMap[size];
                return row && (row[reg] || "");
            };
        }();
        
        var toSegRegName = function() {
            var regMap = ["es", "cs", "ss", "ds"];
            
            return function(reg) {
                return regMap[reg] || "";
            };
        }();
        
        var toRepPrefix = function(prefix) {
            var map = [];
            map[REP_NOTZERO] = "repnz";
            map[REP_ZERO] = "repz";
            return function(prefix) {
                return map[prefix] || "";
            };
        }();
        
        var toAddressingMode = function() {
            var addrModes = [
                "[bx][si]", "[bx][di]", "[bp][si]", "[bp][di]",
                "[si]", "[di]", "[bp]", "[bx]"
            ];
            
            return function(mode) {
                return addrModes[mode] || "";
            };
        }();
        
        
        var pdModRmHelper = function() {
            var ptrs = ["", "byte ptr ", "word ptr ", "", "dword ptr "];
            
            return function(decoded, state, size) {
                var baseIndex = toAddressingMode(decoded.rm);;

                if (!ptrs[size] || !baseIndex) {
                    return "";
                }

                var prefix = toSegRegName(findSegOverride(decoded));
                prefix = (prefix) ? (prefix + ":") : prefix;
                        
                // Displacement only
                if (decoded.mod === MOD_MEM && decoded.rm === RM_DISPONLY) {
                    baseIndex = "[0x" + decoded.disp.toString(16) + "]";
                } else if (decoded.mod === MOD_MEM_REG) {
                    return toGPRegName(decoded.rm, size);
                } else if (decoded.mod === MOD_MEM || decoded.mod === MOD_MEM_DISP8 || decoded.mod === MOD_MEM_DISP16) {
                    if (decoded.disp !== 0) {
                        baseIndex = decoded.disp + baseIndex;
                    }
                } else {
                    return "";
                }

                return ptrs[size] + prefix + baseIndex;
            };
        }();
        
        var findRep = function(decoded) {
            var result;
            (decoded.prefixes || []).forEach(function(item) {
                if (item === REP_ZERO ||
                    item === REP_NOTZERO) {
                    result = item;
                }
            });
            return result;
        };
        
        var findSegOverride = function(decoded) {
            var result;
            (decoded.prefixes || []).forEach(function(item) {
                if (item === SEGOVERRIDE_CS ||
                    item === SEGOVERRIDE_SS ||
                    item === SEGOVERRIDE_DS ||
                    item === SEGOVERRIDE_ES) {
                    result = (item >> 3) & 0x3;
                }
            });
            return result;
        };
        
        var findLock = function(decoded) {
            var result = false;
            (decoded.prefixes || []).forEach(function(item) {
                if (item === LOCK_PREFIX) {
                    result = true;
                }
            });
            return result;
        };
        
        var pdModRm8 = function(decoded, state) {
            return pdModRmHelper(decoded, state, 1);
        };
        
        var pdModRm16 = function(decoded, state) {
            return pdModRmHelper(decoded, state, 2);
        };
        
        var pdReg8 = function(decoded, state) {
            return toGPRegName(decoded.reg, 1);
        };
        
        var pdReg16 = function(decoded, state) {
            return toGPRegName(decoded.reg, 2);
        };
        
        var pdSigned8 = function(decoded, state) {
            return toSigned8(decoded.imm1).toString();
        };
        
        var pdSigned16 = function(decoded, state) {
            return toSigned16(decoded.imm1).toString();
        };
        
        var pdUnsigned8 = function(decoded, state) {
            // There is no difference with the 16 bit version
            return pdSigned16(decoded, state);
        };
        
        var pdUnsigned16 = function(decoded, state) {
            return decoded.imm1.toString();
        };
        
        var pdReg8_2_0 = function(decoded, state) {
            return toGPRegName(decoded.opcode & 0x7, 1);
        };
        
        var pdReg16_2_0 = function(decoded, state) {
            return toGPRegName(decoded.opcode & 0x7, 2);
        };
        
        var pdEA8 = function(decoded, state) {
            return "byte ptr [0x" + decoded.imm1.toString(16) + "]";
        };
        
        var pdEA16 = function(decoded, state) {
            return "word ptr [0x" + decoded.imm1.toString(16) + "]";
        };
        
        var pdRegSeg = function(decoded, state) {
            return toSegRegName(decoded.seg);
        };
        
        var pdXlat = function(decoded, state) {
            var over = findSegOverride(decoded);
            return (toSegRegName(over) || "ds") + ":[bx]";
        };
        
        var pdSegInOpcode = function(decoded, state) {
            return toSegRegName((decoded.opcode >>> 3) & 0x3);
        };
        
        var pdConstant = function() {
            // Table of constants
            var constants = {};
            
            return function(constant) {
                constant = (typeof(constant) === "string") ? constant : constant.toString();
                if (constants.hasOwnProperty(constant)) {
                    return constants[constant];
                } else {
                    constants[constant] = function() {
                        return constant;
                    };
                    return constants[constant];
                }
            };
        }();
        
        var pdOffset8 = function(decoded, state) {
            return "0x" + (state.org + decoded.usedBytes + toSigned8(decoded.imm1)).toString(16);
        };
        
        var pdOffset16 = function(decoded, state) {
            return "0x" + (state.org + decoded.usedBytes + toSigned16(decoded.imm1)).toString(16);
        };

        var pdFarAddress = function(decoded, state) {
            return "0x" + decoded.imm2.toString(16) + ":" + "0x" +
                decoded.imm1.toString(16);
        };
        
        var pdFarIndirect = function(decoded, state) {
            return pdModRmHelper(decoded, state, 4);
        };

        var intelPrinter = {
            toString : function() {
                return (this.prefixes.join(" ") + " " + this.mnemonic + " " + this.args.join(", ")).trim();
            }
        };
        
        // Each mnemonics is at offset 0xOOE where:
        // OO is the first opcode byte
        // E is the optional 3-bit extension, so E should be in range 0-7
        // If there is no extension, E is not present
        var mnemonics = [];
        mnemonics.unroll = function(item, base, iterations, increment) {
            increment = (increment) ? increment : 1;
            for (var i = 0; i < iterations; i++) {
                this[base] = item;
                base += increment;
            }
        };
        // MOV
        mnemonics[0x88]  = { mnemonic : "mov", args : [pdModRm8, pdReg8] };
        mnemonics[0x89]  = { mnemonic : "mov", args : [pdModRm16, pdReg16] };
        mnemonics[0x8A]  = { mnemonic : "mov", args : [pdReg8, pdModRm8] };
        mnemonics[0x8B]  = { mnemonic : "mov", args : [pdReg16, pdModRm16] };
        mnemonics[0xC60] = { mnemonic : "mov", args : [pdModRm8, pdSigned8] };
        mnemonics[0xC70] = { mnemonic : "mov", args : [pdModRm16, pdSigned16] };
        mnemonics.unroll({ mnemonic : "mov", args : [pdReg8_2_0, pdSigned8] }, 0xB0, 8);
        mnemonics.unroll({ mnemonic : "mov", args : [pdReg16_2_0, pdSigned16] }, 0xB8, 8);
        mnemonics[0xA0]  = { mnemonic : "mov", args : [pdConstant("al"), pdEA8] };
        mnemonics[0xA1]  = { mnemonic : "mov", args : [pdConstant("ax"), pdEA16] };
        mnemonics[0xA2]  = { mnemonic : "mov", args : [pdEA8, pdConstant("al")] };
        mnemonics[0xA3]  = { mnemonic : "mov", args : [pdEA16, pdConstant("ax")] };
        mnemonics[0x8E]  = { mnemonic : "mov", args : [pdRegSeg, pdModRm16] };
        mnemonics[0x8C]  = { mnemonic : "mov", args : [pdModRm16, pdRegSeg] };
        
        // PUSH
        mnemonics[0xFF6]  = { mnemonic : "push", args : [pdModRm16] };
        mnemonics.unroll({ mnemonic : "push", args : [pdReg16_2_0] }, 0x50, 8);
        mnemonics.unroll({ mnemonic : "push", args : [pdSegInOpcode] }, 0x06, 4, 8);
        
        // POP
        mnemonics[0x8F0]  = { mnemonic : "pop", args : [pdModRm16] };
        mnemonics.unroll({ mnemonic : "pop", args : [pdReg16_2_0] }, 0x58, 8);
        mnemonics.unroll({ mnemonic : "pop", args : [pdSegInOpcode] }, 0x07, 4, 8);
        
        // XCHG
        mnemonics[0x86]  = { mnemonic : "xchg", args : [pdReg8, pdModRm8] };
        mnemonics[0x87]  = { mnemonic : "xchg", args : [pdReg16, pdModRm16] };
        mnemonics[0x90]  = { mnemonic : "nop"};
        mnemonics.unroll({ mnemonic : "xchg", args : [pdConstant("ax"), pdReg16_2_0] }, 0x91, 7);
        
        // IN
        mnemonics[0xE4]  = { mnemonic : "in", args : [pdConstant("al"), pdUnsigned8] };
        mnemonics[0xE5]  = { mnemonic : "in", args : [pdConstant("ax"), pdUnsigned16] };
        mnemonics[0xEC]  = { mnemonic : "in", args : [pdConstant("al"), pdConstant("dx")] };
        mnemonics[0xED]  = { mnemonic : "in", args : [pdConstant("ax"), pdConstant("dx")] };
        
        // OUT
        mnemonics[0xE4]  = { mnemonic : "out", args : [pdUnsigned8, pdConstant("al")] };
        mnemonics[0xE5]  = { mnemonic : "out", args : [pdUnsigned16, pdConstant("ax")] };
        mnemonics[0xEE]  = { mnemonic : "out", args : [pdConstant("dx"), pdConstant("al")] };
        mnemonics[0xEF]  = { mnemonic : "out", args : [pdConstant("dx"), pdConstant("ax")] };
        
        // XLAT
        mnemonics[0xD7]  = { mnemonic : "xlat", args : [pdXlat] };
        
        // LEA/LES/LDS
        mnemonics[0x8D]  = { mnemonic : "lea", args : [pdReg16, pdModRm16] };
        mnemonics[0xC4]  = { mnemonic : "les", args : [pdReg16, pdModRm16] };
        mnemonics[0xC5]  = { mnemonic : "lds", args : [pdReg16, pdModRm16] };
        
        // LAHF/SAHF
        mnemonics[0x9F]  = { mnemonic : "lahf" };
        mnemonics[0x9E]  = { mnemonic : "sahf" };
        
        // PUSHF/POPF
        mnemonics[0x9D]  = { mnemonic : "popf" };
        
        // ADD
        mnemonics[0x00]  = { mnemonic : "add", args : [pdModRm8, pdReg8] };
        mnemonics[0x01]  = { mnemonic : "add", args : [pdModRm16, pdReg16] };
        mnemonics[0x02]  = { mnemonic : "add", args : [pdReg8, pdModRm8] };
        mnemonics[0x03]  = { mnemonic : "add", args : [pdReg16, pdModRm16] };
        mnemonics[0x800]  = { mnemonic : "add", args : [pdModRm8, pdSigned8] };
        mnemonics[0x810]  = { mnemonic : "add", args : [pdModRm16, pdSigned16] };
        mnemonics[0x820]  = { mnemonic : "add", args : [pdModRm8, pdSigned8] };
        mnemonics[0x830]  = { mnemonic : "add", args : [pdModRm16, pdSigned8] };
        mnemonics[0x04]  = { mnemonic : "add", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x05]  = { mnemonic : "add", args : [pdConstant("ax"), pdSigned16] };
        
        // ADC
        mnemonics[0x10]  = { mnemonic : "adc", args : [pdModRm8, pdReg8] };
        mnemonics[0x11]  = { mnemonic : "adc", args : [pdModRm16, pdReg16] };
        mnemonics[0x12]  = { mnemonic : "adc", args : [pdReg8, pdModRm8] };
        mnemonics[0x13]  = { mnemonic : "adc", args : [pdReg16, pdModRm16] };
        mnemonics[0x802]  = { mnemonic : "adc", args : [pdModRm8, pdSigned8] };
        mnemonics[0x812]  = { mnemonic : "adc", args : [pdModRm16, pdSigned16] };
        mnemonics[0x822]  = { mnemonic : "adc", args : [pdModRm8, pdSigned8] };
        mnemonics[0x832]  = { mnemonic : "adc", args : [pdModRm16, pdSigned8] };
        mnemonics[0x14]  = { mnemonic : "adc", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x15]  = { mnemonic : "adc", args : [pdConstant("ax"), pdSigned16] };
        
        // INC
        mnemonics[0xFE0]  = { mnemonic : "inc", args : [pdModRm8] };
        mnemonics[0xFF0]  = { mnemonic : "inc", args : [pdModRm16] };
        mnemonics.unroll({ mnemonic : "inc", args : [pdReg16_2_0] }, 0x40, 8);
        
        // AAA/DAA
        mnemonics[0x37]  = { mnemonic : "aaa" };
        mnemonics[0x27]  = { mnemonic : "daa" };
        
        // SUB
        mnemonics[0x28]  = { mnemonic : "sub", args : [pdModRm8, pdReg8] };
        mnemonics[0x29]  = { mnemonic : "sub", args : [pdModRm16, pdReg16] };
        mnemonics[0x2A]  = { mnemonic : "sub", args : [pdReg8, pdModRm8] };
        mnemonics[0x2B]  = { mnemonic : "sub", args : [pdReg16, pdModRm16] };
        mnemonics[0x805]  = { mnemonic : "sub", args : [pdModRm8, pdSigned8] };
        mnemonics[0x815]  = { mnemonic : "sub", args : [pdModRm16, pdSigned16] };
        mnemonics[0x825]  = { mnemonic : "sub", args : [pdModRm8, pdSigned8] };
        mnemonics[0x835]  = { mnemonic : "sub", args : [pdModRm16, pdSigned8] };
        mnemonics[0x2C]  = { mnemonic : "sub", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x2D]  = { mnemonic : "sub", args : [pdConstant("ax"), pdSigned16] };
        
        // SBB
        mnemonics[0x18]  = { mnemonic : "sbb", args : [pdModRm8, pdReg8] };
        mnemonics[0x19]  = { mnemonic : "sbb", args : [pdModRm16, pdReg16] };
        mnemonics[0x1A]  = { mnemonic : "sbb", args : [pdReg8, pdModRm8] };
        mnemonics[0x1B]  = { mnemonic : "sbb", args : [pdReg16, pdModRm16] };
        mnemonics[0x803]  = { mnemonic : "sbb", args : [pdModRm8, pdSigned8] };
        mnemonics[0x813]  = { mnemonic : "sbb", args : [pdModRm16, pdSigned16] };
        mnemonics[0x823]  = { mnemonic : "sbb", args : [pdModRm8, pdSigned8] };
        mnemonics[0x833]  = { mnemonic : "sbb", args : [pdModRm16, pdSigned8] };
        mnemonics[0x1C]  = { mnemonic : "sbb", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x1D]  = { mnemonic : "sbb", args : [pdConstant("ax"), pdSigned16] };
        
        // DEC
        mnemonics[0xFE1]  = { mnemonic : "dec", args : [pdModRm8] };
        mnemonics[0xFF1]  = { mnemonic : "dec", args : [pdModRm16] };
        mnemonics.unroll({ mnemonic : "dec", args : [pdReg16_2_0] }, 0x48, 8);
        
        // AAS/DAS/NEG
        mnemonics[0x3F]  = { mnemonic : "aas" };
        mnemonics[0x2F]  = { mnemonic : "das" };
        mnemonics[0xF63]  = { mnemonic : "neg", args : [pdModRm8] };
        mnemonics[0xF73]  = { mnemonic : "neg", args : [pdModRm16] };
        
        // CMP
        mnemonics[0x38]  = { mnemonic : "cmp", args : [pdModRm8, pdReg8] };
        mnemonics[0x39]  = { mnemonic : "cmp", args : [pdModRm16, pdReg16] };
        mnemonics[0x3A]  = { mnemonic : "cmp", args : [pdReg8, pdModRm8] };
        mnemonics[0x3B]  = { mnemonic : "cmp", args : [pdReg16, pdModRm16] };
        mnemonics[0x807]  = { mnemonic : "cmp", args : [pdModRm8, pdSigned8] };
        mnemonics[0x817]  = { mnemonic : "cmp", args : [pdModRm16, pdSigned16] };
        mnemonics[0x827]  = { mnemonic : "cmp", args : [pdModRm8, pdSigned8] };
        mnemonics[0x837]  = { mnemonic : "cmp", args : [pdModRm16, pdSigned8] };
        mnemonics[0x3C]  = { mnemonic : "cmp", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x3D]  = { mnemonic : "cmp", args : [pdConstant("ax"), pdSigned16] };
        
        // MUL/IMUL/DIV/IDIV/AAM/AAD
        mnemonics[0xF64]  = { mnemonic : "mul", args : [pdModRm8] };
        mnemonics[0xF74]  = { mnemonic : "mul", args : [pdModRm16] };
        mnemonics[0xF65]  = { mnemonic : "imul", args : [pdModRm8] };
        mnemonics[0xF75]  = { mnemonic : "imul", args : [pdModRm16] };
        mnemonics[0xF66]  = { mnemonic : "div", args : [pdModRm8] };
        mnemonics[0xF76]  = { mnemonic : "div", args : [pdModRm16] };
        mnemonics[0xF67]  = { mnemonic : "idiv", args : [pdModRm8] };
        mnemonics[0xD4]  = { mnemonic : "aam", args : [pdUnsigned8]};
        mnemonics[0xD5]  = { mnemonic : "aad", args : [pdUnsigned8]};
        
        // CBW/CWD
        mnemonics[0x98]  = { mnemonic : "cbw" };
        mnemonics[0x99]  = { mnemonic : "cwd" };
        
        // NOT
        mnemonics[0xF62]  = { mnemonic : "not", args : [pdModRm8] };
        mnemonics[0xF72]  = { mnemonic : "not", args : [pdModRm16] };
        
        // SHL/SHR/SAR//ROL/ROR
        mnemonics[0xD04]  = { mnemonic : "shl", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD14]  = { mnemonic : "shl", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD24]  = { mnemonic : "shl", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD34]  = { mnemonic : "shl", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD05]  = { mnemonic : "shr", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD15]  = { mnemonic : "shr", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD25]  = { mnemonic : "shr", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD35]  = { mnemonic : "shr", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD07]  = { mnemonic : "sar", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD17]  = { mnemonic : "sar", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD27]  = { mnemonic : "sar", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD37]  = { mnemonic : "sar", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD00]  = { mnemonic : "rol", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD10]  = { mnemonic : "rol", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD20]  = { mnemonic : "rol", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD30]  = { mnemonic : "rol", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD01]  = { mnemonic : "ror", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD11]  = { mnemonic : "ror", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD21]  = { mnemonic : "ror", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD31]  = { mnemonic : "ror", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD02]  = { mnemonic : "rcl", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD12]  = { mnemonic : "rcl", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD22]  = { mnemonic : "rcl", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD32]  = { mnemonic : "rcl", args : [pdModRm16, pdConstant("cl")] };
        mnemonics[0xD03]  = { mnemonic : "rcr", args : [pdModRm8, pdConstant("1")] };
        mnemonics[0xD13]  = { mnemonic : "rcr", args : [pdModRm16, pdConstant("1")] };
        mnemonics[0xD23]  = { mnemonic : "rcr", args : [pdModRm8, pdConstant("cl")] };
        mnemonics[0xD33]  = { mnemonic : "rcr", args : [pdModRm16, pdConstant("cl")] };
        
        // AND
        mnemonics[0x20]  = { mnemonic : "and", args : [pdModRm8, pdReg8] };
        mnemonics[0x21]  = { mnemonic : "and", args : [pdModRm16, pdReg16] };
        mnemonics[0x22]  = { mnemonic : "and", args : [pdReg8, pdModRm8] };
        mnemonics[0x23]  = { mnemonic : "and", args : [pdReg16, pdModRm16] };
        mnemonics[0x804]  = { mnemonic : "and", args : [pdModRm8, pdSigned8] };
        mnemonics[0x814]  = { mnemonic : "and", args : [pdModRm16, pdSigned16] };
        mnemonics[0x24]  = { mnemonic : "and", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x25]  = { mnemonic : "and", args : [pdConstant("ax"), pdSigned16] };
        
        // OR
        mnemonics[0x08]  = { mnemonic : "or", args : [pdModRm8, pdReg8] };
        mnemonics[0x09]  = { mnemonic : "or", args : [pdModRm16, pdReg16] };
        mnemonics[0x0A]  = { mnemonic : "or", args : [pdReg8, pdModRm8] };
        mnemonics[0x0B]  = { mnemonic : "or", args : [pdReg16, pdModRm16] };
        mnemonics[0x801]  = { mnemonic : "or", args : [pdModRm8, pdSigned8] };
        mnemonics[0x811]  = { mnemonic : "or", args : [pdModRm16, pdSigned16] };
        mnemonics[0x0C]  = { mnemonic : "or", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x0D]  = { mnemonic : "or", args : [pdConstant("ax"), pdSigned16] };
        
        // XOR
        mnemonics[0x30]  = { mnemonic : "xor", args : [pdModRm8, pdReg8] };
        mnemonics[0x31]  = { mnemonic : "xor", args : [pdModRm16, pdReg16] };
        mnemonics[0x32]  = { mnemonic : "xor", args : [pdReg8, pdModRm8] };
        mnemonics[0x33]  = { mnemonic : "xor", args : [pdReg16, pdModRm16] };
        mnemonics[0x806]  = { mnemonic : "xor", args : [pdModRm8, pdSigned8] };
        mnemonics[0x816]  = { mnemonic : "xor", args : [pdModRm16, pdSigned16] };
        mnemonics[0x34]  = { mnemonic : "xor", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0x35]  = { mnemonic : "xor", args : [pdConstant("ax"), pdSigned16] };
        
        // TEST
        mnemonics[0x84]  = { mnemonic : "test", args : [pdModRm8, pdReg8] };
        mnemonics[0x85]  = { mnemonic : "test", args : [pdModRm16, pdReg16] };
        mnemonics[0xF60]  = { mnemonic : "test", args : [pdModRm8, pdSigned8] };
        mnemonics[0xF70]  = { mnemonic : "test", args : [pdModRm16, pdSigned16] };
        mnemonics[0xA8]  = { mnemonic : "test", args : [pdConstant("al"), pdSigned8] };
        mnemonics[0xA9]  = { mnemonic : "test", args : [pdConstant("ax"), pdSigned16] };
        
        // String instructions
        mnemonics[0xA4]  = { mnemonic : "movsb" };
        mnemonics[0xA5]  = { mnemonic : "movsw" };
        mnemonics[0xA6]  = { mnemonic : "cmpsb" };
        mnemonics[0xA7]  = { mnemonic : "cmpsw" };
        mnemonics[0xAE]  = { mnemonic : "scasb" };
        mnemonics[0xAF]  = { mnemonic : "scasw" };
        mnemonics[0xAC]  = { mnemonic : "lodsb" };
        mnemonics[0xAD]  = { mnemonic : "lodww" };
        mnemonics[0xAA]  = { mnemonic : "stosb" };
        mnemonics[0xAB]  = { mnemonic : "stosw" };
        
        // INT
        mnemonics[0xCD]  = { mnemonic : "int", args : [pdUnsigned8] };
        mnemonics[0xCC]  = { mnemonic : "int", args : [pdConstant("3")] };
        
        // CALL
        mnemonics[0xE8]  = { mnemonic : "call", args : [pdOffset16] };
        mnemonics[0xFF2]  = { mnemonic : "call", args : [pdModRm16] };
        mnemonics[0x9A]  = { mnemonic : "call", args : [pdFarAddress] };
        mnemonics[0xFF3]  = { mnemonic : "call", args : [pdFarIndirect] };
        
        // JMP
        mnemonics[0xE9]  = { mnemonic : "jmp", args : [pdOffset16] };
        mnemonics[0xEB]  = { mnemonic : "jmp", args : [pdOffset8] };
        mnemonics[0xFF4]  = { mnemonic : "jmp", args : [pdModRm16] };
        mnemonics[0xEA]  = { mnemonic : "jmp", args : [pdFarAddress] };
        mnemonics[0xFF5]  = { mnemonic : "jmp", args : [pdFarIndirect] };
        
        // RET
        mnemonics[0xC3]  = { mnemonic : "retn" };
        mnemonics[0xCB]  = { mnemonic : "retf" };
        mnemonics[0xC2]  = { mnemonic : "retn", args : [pdSigned16] };
        mnemonics[0xCA]  = { mnemonic : "retf", args : [pdSigned16] };
        
        // Conditional jumps and LOOP/JCXZ
        mnemonics[0x74]  = { mnemonic : "jz", args : [pdOffset8] };
        mnemonics[0x7C]  = { mnemonic : "jl", args : [pdOffset8] };
        mnemonics[0x7E]  = { mnemonic : "jle", args : [pdOffset8] };
        mnemonics[0x72]  = { mnemonic : "jb", args : [pdOffset8] };
        mnemonics[0x76]  = { mnemonic : "jbe", args : [pdOffset8] };
        mnemonics[0x7A]  = { mnemonic : "jp", args : [pdOffset8] };
        mnemonics[0x70]  = { mnemonic : "jo", args : [pdOffset8] };
        mnemonics[0x78]  = { mnemonic : "js", args : [pdOffset8] };
        mnemonics[0x72]  = { mnemonic : "jb", args : [pdOffset8] };
        mnemonics[0x75]  = { mnemonic : "jnz", args : [pdOffset8] };
        mnemonics[0x7D]  = { mnemonic : "jge", args : [pdOffset8] };
        mnemonics[0x7F]  = { mnemonic : "jg", args : [pdOffset8] };
        mnemonics[0x73]  = { mnemonic : "jae", args : [pdOffset8] };
        mnemonics[0x77]  = { mnemonic : "ja", args : [pdOffset8] };
        mnemonics[0x7B]  = { mnemonic : "jnp", args : [pdOffset8] };
        mnemonics[0x71]  = { mnemonic : "jno", args : [pdOffset8] };
        mnemonics[0x79]  = { mnemonic : "jns", args : [pdOffset8] };
        mnemonics[0xE2]  = { mnemonic : "loop", args : [pdOffset8] };
        mnemonics[0xE1]  = { mnemonic : "loopz", args : [pdOffset8] };
        mnemonics[0xE0]  = { mnemonic : "loopnz", args : [pdOffset8] };
        mnemonics[0xE3]  = { mnemonic : "jcxz", args : [pdOffset8] };
        
        // Flags/various
        mnemonics[0xF8]  = { mnemonic : "clc" };
        mnemonics[0xF5]  = { mnemonic : "cmc" };
        mnemonics[0xF9]  = { mnemonic : "stc" };
        mnemonics[0xFC]  = { mnemonic : "cld" };
        mnemonics[0xFD]  = { mnemonic : "std" };
        mnemonics[0xFA]  = { mnemonic : "cli" };
        mnemonics[0xFB]  = { mnemonic : "sti" };
        mnemonics[0xF4]  = { mnemonic : "hlt" };
        mnemonics[0x9B]  = { mnemonic : "wait" };
        
        
        return {
            "format" : function(decoded) {
                var fullOpcode = decoded.opcode;
                var descriptor, result = Object.create(intelPrinter);
                if (typeof(decoded.ext) !== "undefined") {
                    fullOpcode = fullOpcode * 16 + decoded.ext;
                }
                descriptor = mnemonics[fullOpcode];
                result.mnemonic = descriptor.mnemonic;
                result.prefixes = [];
                var repPrefix = findRep(decoded);
                if (repPrefix) {
                    result.prefixes.push(toRepPrefix(repPrefix));
                }
                var hasLock = findLock(decoded);
                if (hasLock) {
                    result.prefixes.push("lock");
                }
                result.args = [];
                (descriptor.args || []).forEach(function (item) {
                    var px = item(decoded, state);
                    if (!px) {
                        throwIt(EXCEPTION_BADOPSTRUCT, "Cannot format malformed opcode structure", { "decoded" : decoded });
                    }
                    result.args.push(px);
                });
                state.org += decoded.usedBytes;

                return result;
            }
        };
    };
    js86.makeIntelSyntaxFormatter = makeIntelSyntaxFormatter;

    var makeDisassembler = js86.makeDisassembler = function(params_) {
        // Params represent the configuration parameters affecting how this
        // disassembler works. Currently unused.
        var params = params_ || {};
        
        var disassemble = function disassemble(info) {
            // info may contain a partially decoded object from a previous call to
            // disassemble holding instruction prefixes. As of now they are not
            // used since they do not change the way instructions are to be decoded.
            // However should we ever want to switch to 32 bit instructions
            // we would need to now them before trying to interpret instructions
            // i.e. a 32 bit instruction with an address size override needs
            // a different interpretation of the MOD/REG/RM byte
            var decoded = info.decoded || {};
            var opcodes = info.opcodes;
            var opcode;
            var handler;
            var startOffset;
            
            var myInfo = {
                disassemble : info.disassemble || disassemble,
                opcodes : opcodes,
                decoded : decoded
            };
                
            try {
                startOffset = opcodes.getPosition();
                opcode = opcodes.getByte();
                decoded.opcode = opcode;
                handler = opcodeToDecodingClass[opcode];
                if (!handler) {
                    throwIt(
                        EXCEPTION_BADOPCODE,
                        "Unknown instruction",
                        {stream : opcodes}
                    );
                }
                handler(myInfo);
            } catch (e) {
                opcodes.putback();
                if (e.name === EXCEPTION_ENDOFSTREAM) {
                    throwIt(EXCEPTION_BADOPCODE, "Unknown instruction", {"stream" : opcodes});
                }
                throw e;
            }
            opcodes.discard();
            decoded.usedBytes = opcodes.getPosition() - startOffset;
            return decoded;
        };
        
        var disassembleAll = function(info) {
            var callback = info.callback || function() {};
            var errCallback = info.errCallback || function() {};
            var opcodes = info.opcodes;
            while(!opcodes.isEof()) {
                try {
                    callback(disassemble({ "opcodes" : opcodes  }));
                } catch (e) {
                    if (e.name === EXCEPTION_BADOPCODE) {
                        if (!errCallback(e.extra.stream)) {
                            // Skip one byte
                            opcodes.getByte();
                            opcodes.discard();
                        }
                        continue;
                    }
                    throw e;
                }
            }
        };
        
        return {
            // Disassembles one instruction from a stream
            "disassemble" : function(info) {
                // This function ensures that only intended arguments are propagated to
                // the internal "disassemble", removing any property that could interfere
                // with recursion, since disassemble can indirectly call itself
                disassemble({opcodes : info.opcodes});
            },
            
            // Disassembles everything of to enf of the stream
            "disassembleAll" : disassembleAll
        };
    };

    return js86;
}());
