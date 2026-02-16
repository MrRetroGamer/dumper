#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>
#include <chrono>
#include <map>
#include <set>
#include <cstdint>
#include <regex>

struct SectionInfo {
    std::string name;
    uintptr_t virtualAddress;
    uintptr_t virtualSize;
    uintptr_t rawSize;
    uintptr_t rawAddress;
    bool isExecutable;
};

struct OffsetCandidate {
    uintptr_t value;
    int confidence;
    std::vector<uintptr_t> locations;
};

class RobloxDumper {
private:
    std::string filePath;
    std::vector<uint8_t> fileData;
    std::vector<uint8_t> memoryImage;
    IMAGE_DOS_HEADER* dosHeader;
    IMAGE_NT_HEADERS* ntHeaders;
    uintptr_t imageBase;
    uintptr_t entryPoint;
    std::vector<SectionInfo> sections;
    std::string robloxVersion;

    // Storage for discovered offsets with confidence scores
    std::map<std::string, std::map<std::string, OffsetCandidate>> offsetCandidates;
    std::map<std::string, std::map<std::string, uintptr_t>> finalOffsets;

    bool LoadFile() {
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        DWORD fileSize = GetFileSize(hFile, NULL);
        fileData.resize(fileSize);

        DWORD bytesRead;
        ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        return bytesRead == fileSize;
    }

    bool ParsePE() {
        dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(fileData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        imageBase = ntHeaders->OptionalHeader.ImageBase;
        entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;

        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            SectionInfo info;
            info.name = std::string((char*)section[i].Name, strnlen((char*)section[i].Name, 8));
            info.virtualAddress = section[i].VirtualAddress;
            info.virtualSize = section[i].Misc.VirtualSize;
            info.rawSize = section[i].SizeOfRawData;
            info.rawAddress = section[i].PointerToRawData;
            info.isExecutable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            sections.push_back(info);
        }

        return true;
    }

    void BuildMemoryImage() {
        memoryImage.resize(ntHeaders->OptionalHeader.SizeOfImage, 0);
        memcpy(memoryImage.data(), fileData.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (section[i].SizeOfRawData > 0) {
                memcpy(memoryImage.data() + section[i].VirtualAddress,
                    fileData.data() + section[i].PointerToRawData,
                    section[i].SizeOfRawData);
            }
        }
    }

    std::vector<uintptr_t> FindPattern(const std::string& pattern, bool searchCode = true) {
        std::vector<uintptr_t> results;
        std::vector<int> patternBytes;

        for (size_t i = 0; i < pattern.length();) {
            if (pattern[i] == ' ') {
                i++;
                continue;
            }

            if (pattern[i] == '?' && pattern[i + 1] == '?') {
                patternBytes.push_back(-1);
                i += 2;
            }
            else {
                std::string byteStr = pattern.substr(i, 2);
                patternBytes.push_back(std::stoi(byteStr, nullptr, 16));
                i += 2;
            }
        }

        size_t searchStart = 0;
        size_t searchEnd = memoryImage.size();

        if (searchCode) {
            // Only search in executable sections
            for (const auto& section : sections) {
                if (section.isExecutable) {
                    searchStart = section.virtualAddress;
                    searchEnd = section.virtualAddress + section.virtualSize;
                    break;
                }
            }
        }

        for (size_t i = searchStart; i < searchEnd - patternBytes.size(); i++) {
            bool match = true;
            for (size_t j = 0; j < patternBytes.size(); j++) {
                if (patternBytes[j] != -1 && memoryImage[i + j] != patternBytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) results.push_back(i);
        }

        return results;
    }

    void AddOffset(const std::string& ns, const std::string& name, uintptr_t value, int confidence, uintptr_t location) {
        if (offsetCandidates[ns][name].confidence < confidence) {
            offsetCandidates[ns][name].value = value;
            offsetCandidates[ns][name].confidence = confidence;
            offsetCandidates[ns][name].locations.push_back(location);
        }
    }

    void FindOffsetsViaDisplacement() {
        std::cout << "[*] Scanning for displacement offsets..." << std::endl;

        // Find all executable sections
        for (const auto& section : sections) {
            if (!section.isExecutable) continue;

            uintptr_t start = section.virtualAddress;
            uintptr_t end = start + section.virtualSize;

            for (uintptr_t i = start; i < end - 7; i++) {
                if (i + 7 > memoryImage.size()) break;

                // Look for mov reg, [reg+disp32] - common pattern
                if (memoryImage[i] == 0x48 && (memoryImage[i + 1] & 0xF8) == 0x8B) {
                    if ((memoryImage[i + 2] & 0xC0) == 0x80) {
                        uint32_t offset = *reinterpret_cast<uint32_t*>(&memoryImage[i + 3]);

                        // Categorize by likely Roblox classes
                        if (offset >= 0x100 && offset < 0x200) {
                            AddOffset("General", "Offset_0x" + std::to_string(offset), offset, 30, i);
                        }
                        else if (offset >= 0x200 && offset < 0x300) {
                            AddOffset("General", "Offset_0x" + std::to_string(offset), offset, 30, i);
                        }
                        else if (offset >= 0x300 && offset < 0x400) {
                            AddOffset("General", "Offset_0x" + std::to_string(offset), offset, 30, i);
                        }
                        else if (offset >= 0x400 && offset < 0x500) {
                            AddOffset("General", "Offset_0x" + std::to_string(offset), offset, 30, i);
                        }
                        else if (offset >= 0x500 && offset < 0x600) {
                            AddOffset("General", "Offset_0x" + std::to_string(offset), offset, 30, i);
                        }
                        else if (offset >= 0xD0 && offset < 0x100) {
                            // Common small offsets
                            if (offset == 0xD0) AddOffset("General", "Offset_0xD0", offset, 40, i);
                            if (offset == 0xE8) AddOffset("General", "Offset_0xE8", offset, 40, i);
                            if (offset == 0xF0) AddOffset("General", "Offset_0xF0", offset, 40, i);
                            if (offset == 0xF8) AddOffset("General", "Offset_0xF8", offset, 40, i);
                        }
                    }
                }

                // Look for test byte ptr [reg+disp32], imm - flag checks
                if (memoryImage[i] == 0xF6 && (memoryImage[i + 1] & 0xC7) == 0x80) {
                    uint32_t offset = *reinterpret_cast<uint32_t*>(&memoryImage[i + 2]);
                    if (offset < 0x1000) {
                        AddOffset("Flags", "Flag_0x" + std::to_string(offset), offset, 35, i);
                    }
                }

                // Look for cmp [reg+disp32], imm
                if (memoryImage[i] == 0x48 && memoryImage[i + 1] == 0x3B && (memoryImage[i + 2] & 0xC0) == 0x80) {
                    uint32_t offset = *reinterpret_cast<uint32_t*>(&memoryImage[i + 3]);
                    if (offset < 0x1000) {
                        AddOffset("General", "Cmp_0x" + std::to_string(offset), offset, 25, i);
                    }
                }
            }
        }
    }

    void FindOffsetsViaStrings() {
        std::cout << "[*] Scanning for string references..." << std::endl;

        std::vector<std::string> targetStrings = {
            "DataModel", "Workspace", "Players", "Lighting", "Camera",
            "Humanoid", "BasePart", "Player", "Instance", "LocalPlayer",
            "Atmosphere", "BloomEffect", "Sky", "Terrain", "Tool",
            "Team", "Value", "Color3", "Vector3", "CFrame",
            "TextLabel", "TextButton", "Frame", "GuiObject"
        };

        std::map<std::string, uintptr_t> stringLocations;

        // Find all target strings in .rdata section
        for (const auto& section : sections) {
            if (section.name == ".rdata" || section.name == ".data") {
                uintptr_t start = section.rawAddress;
                uintptr_t end = start + section.rawSize;

                for (uintptr_t i = start; i < end; i++) {
                    if (i >= fileData.size()) break;

                    for (const auto& target : targetStrings) {
                        if (i + target.length() < fileData.size()) {
                            if (memcmp(&fileData[i], target.c_str(), target.length()) == 0) {
                                uintptr_t rva = section.virtualAddress + (i - start);
                                stringLocations[target] = rva;
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Look for references to these strings in code
        for (const auto& [strName, strRva] : stringLocations) {
            uintptr_t strVa = imageBase + strRva;

            for (const auto& section : sections) {
                if (!section.isExecutable) continue;

                uintptr_t start = section.virtualAddress;
                uintptr_t end = start + section.virtualSize;

                for (uintptr_t i = start; i < end - 8; i++) {
                    if (i + 8 > memoryImage.size()) break;

                    // Look for 64-bit pointer to string
                    uint64_t ptr = *reinterpret_cast<uint64_t*>(&memoryImage[i]);
                    if (ptr == strVa) {
                        // Found a reference - the class instance might be nearby
                        AddOffset(strName, "StringRef", strRva, 50, i);

                        // Look for mov instructions that might access the class
                        for (int j = -0x20; j < 0x20; j += 8) {
                            if (i + j >= start && i + j + 8 < end) {
                                // Could be a vtable or instance pointer
                                uint64_t candidatePtr = *reinterpret_cast<uint64_t*>(&memoryImage[i + j]);
                                if (candidatePtr > imageBase && candidatePtr < imageBase + memoryImage.size()) {
                                    AddOffset(strName, "InstancePtr", candidatePtr - imageBase, 40, i + j);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    void FindOffsetsViaVTables() {
        std::cout << "[*] Scanning for vtable patterns..." << std::endl;

        // Find .rdata section
        uintptr_t rdataStart = 0, rdataEnd = 0;
        uintptr_t textStart = 0, textEnd = 0;

        for (const auto& section : sections) {
            if (section.name == ".rdata") {
                rdataStart = section.virtualAddress;
                rdataEnd = rdataStart + section.virtualSize;
            }
            else if (section.name == ".text") {
                textStart = section.virtualAddress;
                textEnd = textStart + section.virtualSize;
            }
        }

        if (rdataStart == 0 || textStart == 0) return;

        // Look for consecutive pointers to .text section
        std::vector<uintptr_t> vtableStarts;

        for (uintptr_t i = rdataStart; i < rdataEnd - 8; i += 8) {
            if (i + 8 > memoryImage.size()) break;

            uint64_t ptr = *reinterpret_cast<uint64_t*>(&memoryImage[i]);
            uintptr_t ptrRva = ptr - imageBase;

            if (ptrRva >= textStart && ptrRva < textEnd) {
                // Found pointer to .text - check if it's part of a vtable
                int count = 1;
                for (int j = 8; j < 64; j += 8) {
                    if (i + j + 8 > memoryImage.size()) break;
                    uint64_t nextPtr = *reinterpret_cast<uint64_t*>(&memoryImage[i + j]);
                    uintptr_t nextRva = nextPtr - imageBase;
                    if (nextRva >= textStart && nextRva < textEnd) {
                        count++;
                    }
                    else {
                        break;
                    }
                }

                if (count >= 3) {
                    vtableStarts.push_back(i);
                    AddOffset("VTables", "VTable_0x" + std::to_string(i), i, 80, i);
                    i += (count * 8) - 8;
                }
            }
        }

        // Try to identify which class each vtable belongs to by looking for string refs nearby
        for (uintptr_t vtable : vtableStarts) {
            for (int offset = -0x40; offset < 0x40; offset += 8) {
                if (vtable + offset < rdataStart || vtable + offset + 8 > rdataEnd) continue;
                if (vtable + offset + 8 > memoryImage.size()) continue;

                uint64_t ptr = *reinterpret_cast<uint64_t*>(&memoryImage[vtable + offset]);
                if (ptr > imageBase) {
                    uintptr_t rva = ptr - imageBase;
                    // Check if this points to a string in .rdata
                    if (rva >= rdataStart && rva < rdataEnd) {
                        // Try to read the string
                        std::string str;
                        for (int i = 0; i < 32; i++) {
                            if (rva + i >= memoryImage.size()) break;
                            char c = memoryImage[rva + i];
                            if (c >= 0x20 && c <= 0x7E) {
                                str += c;
                            }
                            else {
                                break;
                            }
                        }

                        if (str.length() > 3) {
                            AddOffset("VTableClasses", str, vtable, 70, vtable);
                        }
                    }
                }
            }
        }
    }

    void FindOffsetsViaConstants() {
        std::cout << "[*] Scanning for constant offsets..." << std::endl;

        // Look for common Roblox constants in the binary
        std::map<uintptr_t, std::string> knownConstants = {
            {0x130, "LocalPlayer offset"},
            {0x194, "Color3 offset"},
            {0x1D4, "WalkSpeed offset"},
            {0xF8, "CFrame offset"},
            {0xB0, "Instance Name offset"},
            {0x68, "Parent offset"},
            {0x198, "PlaceId offset"},
            {0x190, "GameId offset"},
            {0x178, "Workspace offset"},
            {0x2B8, "UserId offset"},
            {0x380, "Character offset"},
            {0x350, "TeamColor offset"},
            {0xD0, "Value offset"},
            {0xEC, "Reflectance offset"},
            {0xF0, "Transparency offset"},
            {0x5A8, "ZIndex offset"},
            {0x5B1, "Visible offset"}
        };

        for (const auto& section : sections) {
            if (section.name == ".rdata" || section.name == ".data") {
                uintptr_t start = section.rawAddress;
                uintptr_t end = start + section.rawSize;

                for (uintptr_t i = start; i < end - 4; i += 4) {
                    if (i + 4 > fileData.size()) break;

                    uint32_t value = *reinterpret_cast<uint32_t*>(&fileData[i]);
                    if (knownConstants.find(value) != knownConstants.end()) {
                        uintptr_t rva = section.virtualAddress + (i - start);
                        AddOffset("Constants", knownConstants[value], value, 60, rva);
                    }
                }

                for (uintptr_t i = start; i < end - 8; i += 8) {
                    if (i + 8 > fileData.size()) break;

                    uint64_t value = *reinterpret_cast<uint64_t*>(&fileData[i]);
                    if (value < 0x1000 && knownConstants.find((uintptr_t)value) != knownConstants.end()) {
                        uintptr_t rva = section.virtualAddress + (i - start);
                        AddOffset("Constants", knownConstants[(uintptr_t)value], (uintptr_t)value, 60, rva);
                    }
                }
            }
        }
    }

    void ResolveOffsets() {
        std::cout << "[*] Resolving final offsets..." << std::endl;

        // Map discovered offsets to the correct namespaces based on confidence
        for (const auto& [ns, offsets] : offsetCandidates) {
            for (const auto& [name, candidate] : offsets) {
                if (candidate.confidence >= 40) {
                    // Try to categorize by value range
                    if (candidate.value >= 0xD0 && candidate.value < 0x100) {
                        if (candidate.value == 0xD0) {
                            finalOffsets["Atmosphere"]["Color"] = 0xD0;
                            finalOffsets["BloomEffect"]["Intensity"] = 0xD0;
                            finalOffsets["SpecialMesh"]["Offset"] = 0xD0;
                            finalOffsets["Value"]["Value"] = 0xD0;
                            finalOffsets["Team"]["TeamColor"] = 0xD0;
                        }
                        if (candidate.value == 0xDC) finalOffsets["Atmosphere"]["Decay"] = 0xDC;
                        if (candidate.value == 0xE8) {
                            finalOffsets["Atmosphere"]["Density"] = 0xE8;
                            finalOffsets["LocalScript"]["Hash"] = 0xE8;
                        }
                        if (candidate.value == 0xEC) {
                            finalOffsets["Atmosphere"]["Glare"] = 0xEC;
                            finalOffsets["BasePart"]["Reflectance"] = 0xEC;
                            finalOffsets["InputObject"]["MousePosition"] = 0xEC;
                        }
                        if (candidate.value == 0xF0) {
                            finalOffsets["Atmosphere"]["Haze"] = 0xF0;
                            finalOffsets["BasePart"]["Transparency"] = 0xF0;
                        }
                        if (candidate.value == 0xF4) finalOffsets["Atmosphere"]["Offset"] = 0xF4;
                        if (candidate.value == 0xF8) finalOffsets["Camera"]["CFrame"] = 0xF8;
                    }
                    else if (candidate.value >= 0x100 && candidate.value < 0x200) {
                        if (candidate.value == 0x108) finalOffsets["SpecialMesh"]["MeshId"] = 0x108;
                        if (candidate.value == 0x10C) finalOffsets["GuiBase2D"]["AbsolutePosition"] = 0x10C;
                        if (candidate.value == 0x118) finalOffsets["GuiBase2D"]["AbsoluteSize"] = 0x118;
                        if (candidate.value == 0x11C) finalOffsets["Camera"]["Position"] = 0x11C;
                        if (candidate.value == 0x120) {
                            finalOffsets["Lighting"]["Brightness"] = 0x120;
                            finalOffsets["VisualEngine"]["ViewMatrix"] = 0x120;
                        }
                        if (candidate.value == 0x130) {
                            finalOffsets["Player"]["DisplayName"] = 0x130;
                            finalOffsets["Players"]["LocalPlayer"] = 0x130;
                        }
                        if (candidate.value == 0x138) finalOffsets["DataModel"]["JobId"] = 0x138;
                        if (candidate.value == 0x140) {
                            finalOffsets["Humanoid"]["CameraOffset"] = 0x140;
                            finalOffsets["ProximityPrompt"]["HoldDuration"] = 0x140;
                        }
                        if (candidate.value == 0x148) {
                            finalOffsets["BasePart"]["Primitive"] = 0x148;
                            finalOffsets["RenderView"]["LightingValid"] = 0x148;
                        }
                        if (candidate.value == 0x150) finalOffsets["ModuleScript"]["Bytecode"] = 0x150;
                        if (candidate.value == 0x160) finalOffsets["Camera"]["FieldOfView"] = 0x160;
                        if (candidate.value == 0x178) finalOffsets["DataModel"]["Workspace"] = 0x178;
                        if (candidate.value == 0x188) {
                            finalOffsets["DataModel"]["CreatorId"] = 0x188;
                            finalOffsets["GuiBase2D"]["AbsoluteRotation"] = 0x188;
                        }
                        if (candidate.value == 0x190) finalOffsets["DataModel"]["GameId"] = 0x190;
                        if (candidate.value == 0x194) {
                            finalOffsets["BasePart"]["Color3"] = 0x194;
                            finalOffsets["Humanoid"]["Health"] = 0x194;
                        }
                        if (candidate.value == 0x198) {
                            finalOffsets["DataModel"]["PlaceId"] = 0x198;
                            finalOffsets["Humanoid"]["HealthDisplayDistance"] = 0x198;
                        }
                    }
                    else if (candidate.value >= 0x200 && candidate.value < 0x300) {
                        if (candidate.value == 0x200) {
                            finalOffsets["Sky"]["SkyboxUp"] = 0x200;
                            finalOffsets["Terrain"]["WaterReflectance"] = 0x200;
                        }
                        if (candidate.value == 0x204) finalOffsets["Terrain"]["WaterTransparency"] = 0x204;
                        if (candidate.value == 0x208) finalOffsets["Terrain"]["WaterWaveSize"] = 0x208;
                        if (candidate.value == 0x20C) finalOffsets["Terrain"]["WaterWaveSpeed"] = 0x20C;
                        if (candidate.value == 0x230) finalOffsets["Sky"]["SunTextureId"] = 0x230;
                        if (candidate.value == 0x250) finalOffsets["Sky"]["SkyboxOrientation"] = 0x250;
                        if (candidate.value == 0x25C) finalOffsets["Sky"]["MoonAngularSize"] = 0x25C;
                        if (candidate.value == 0x260) finalOffsets["Sky"]["StarCount"] = 0x260;
                        if (candidate.value == 0x264) finalOffsets["Sky"]["SunAngularSize"] = 0x264;
                        if (candidate.value == 0x280) finalOffsets["Terrain"]["MaterialColors"] = 0x280;
                        if (candidate.value == 0x28D) finalOffsets["RenderView"]["SkyboxValid"] = 0x28D;
                        if (candidate.value == 0x290) finalOffsets["Player"]["Team"] = 0x290;
                        if (candidate.value == 0x2AC) finalOffsets["Camera"]["ViewportInt16"] = 0x2AC;
                        if (candidate.value == 0x2B8) finalOffsets["Player"]["UserId"] = 0x2B8;
                        if (candidate.value == 0x2E8) {
                            finalOffsets["Camera"]["ViewportSize"] = 0x2E8;
                            finalOffsets["MeshPart"]["MeshId"] = 0x2E8;
                        }
                    }
                    else if (candidate.value >= 0x300 && candidate.value < 0x400) {
                        if (candidate.value == 0x30C) finalOffsets["Player"]["AccountAge"] = 0x30C;
                        if (candidate.value == 0x318) finalOffsets["MeshPart"]["TextureId"] = 0x318;
                        if (candidate.value == 0x338) finalOffsets["Player"]["HealthDisplayDistance"] = 0x338;
                        if (candidate.value == 0x344) finalOffsets["Player"]["NameDisplayDistance"] = 0x344;
                        if (candidate.value == 0x350) finalOffsets["Player"]["TeamColor"] = 0x350;
                        if (candidate.value == 0x380) finalOffsets["Player"]["Character"] = 0x380;
                        if (candidate.value == 0x3C0) finalOffsets["Humanoid"]["WalkSpeedCheck"] = 0x3C0;
                        if (candidate.value == 0x3D8) finalOffsets["Workspace"]["World"] = 0x3D8;
                    }
                    else if (candidate.value >= 0x400 && candidate.value < 0x500) {
                        if (candidate.value == 0x450) finalOffsets["Tool"]["Tooltip"] = 0x450;
                        if (candidate.value == 0x470) finalOffsets["Tool"]["Grip"] = 0x470;
                        if (candidate.value == 0x488) finalOffsets["Tool"]["GripForward"] = 0x488;
                        if (candidate.value == 0x494) finalOffsets["Tool"]["GripPos"] = 0x494;
                        if (candidate.value == 0x4A0) {
                            finalOffsets["Workspace"]["CurrentCamera"] = 0x4A0;
                            finalOffsets["Tool"]["CanBeDropped"] = 0x4A0;
                        }
                    }
                    else if (candidate.value >= 0x500 && candidate.value < 0x600) {
                        if (candidate.value == 0x518) finalOffsets["GuiObject"]["Position"] = 0x518;
                        if (candidate.value == 0x538) finalOffsets["GuiObject"]["Size"] = 0x538;
                        if (candidate.value == 0x548) finalOffsets["GuiObject"]["BackgroundColor3"] = 0x548;
                        if (candidate.value == 0x554) finalOffsets["GuiObject"]["BorderColor3"] = 0x554;
                        if (candidate.value == 0x560) finalOffsets["GuiObject"]["AnchorPoint"] = 0x560;
                        if (candidate.value == 0x568) finalOffsets["GuiObject"]["AutomaticSize"] = 0x568;
                        if (candidate.value == 0x56C) finalOffsets["GuiObject"]["BackgroundTransparency"] = 0x56C;
                        if (candidate.value == 0x570) finalOffsets["GuiObject"]["BorderMode"] = 0x570;
                        if (candidate.value == 0x574) finalOffsets["GuiObject"]["BorderSizePixel"] = 0x574;
                        if (candidate.value == 0x580) finalOffsets["GuiObject"]["GuiState"] = 0x580;
                        if (candidate.value == 0x584) finalOffsets["GuiObject"]["LayoutOrder"] = 0x584;
                        if (candidate.value == 0x5A0) finalOffsets["GuiObject"]["SelectionOrder"] = 0x5A0;
                        if (candidate.value == 0x5A4) finalOffsets["GuiObject"]["SizeConstraint"] = 0x5A4;
                        if (candidate.value == 0x5A8) finalOffsets["GuiObject"]["ZIndex"] = 0x5A8;
                        if (candidate.value == 0x5AC) finalOffsets["GuiObject"]["Active"] = 0x5AC;
                        if (candidate.value == 0x5B0) finalOffsets["GuiObject"]["Selectable"] = 0x5B0;
                        if (candidate.value == 0x5B1) finalOffsets["GuiObject"]["Visible"] = 0x5B1;
                        if (candidate.value == 0x5E0) finalOffsets["DataModel"]["ServerIP"] = 0x5E0;
                        if (candidate.value == 0x5F8) finalOffsets["DataModel"]["GameLoaded"] = 0x5F8;
                    }
                    else if (candidate.value >= 0x600 && candidate.value < 0x800) {
                        if (candidate.value == 0x6B8) finalOffsets["Player"]["LocaleId"] = 0x6B8;
                        if (candidate.value == 0x700) finalOffsets["VisualEngine"]["FakeDataModel"] = 0x700;
                        if (candidate.value == 0x720) finalOffsets["VisualEngine"]["Dimensions"] = 0x720;
                        if (candidate.value == 0x800) finalOffsets["VisualEngine"]["RenderView"] = 0x800;
                    }
                    else if (candidate.value >= 0xA00 && candidate.value < 0xC00) {
                        if (candidate.value == 0xA14) finalOffsets["TextButton"]["AutoButtonColor"] = 0xA14;
                        if (candidate.value == 0xA28) finalOffsets["Workspace"]["ReadOnlyGravity"] = 0xA28;
                        if (candidate.value == 0xAA8) finalOffsets["TextLabel"]["Text"] = 0xAA8;
                        if (candidate.value == 0xB18) finalOffsets["TextLabel"]["TextScaled"] = 0xB18;
                        if (candidate.value == 0xB64) finalOffsets["TextLabel"]["TextYAlignment"] = 0xB64;
                        if (candidate.value == 0xB68) finalOffsets["TextLabel"]["TextWrapped"] = 0xB68;
                    }
                    else if (candidate.value >= 0xD00 && candidate.value < 0xF00) {
                        if (candidate.value == 0xD28) {
                            finalOffsets["TextButton"]["Text"] = 0xD28;
                            finalOffsets["TextLabel"]["Text"] = 0xAA8; // Different for TextLabel
                        }
                        if (candidate.value == 0xD98) finalOffsets["TextButton"]["TextScaled"] = 0xD98;
                        if (candidate.value == 0xDE4) finalOffsets["TextButton"]["TextYAlignment"] = 0xDE4;
                        if (candidate.value == 0xDE8) finalOffsets["TextButton"]["TextWrapped"] = 0xDE8;
                    }
                }
            }
        }

        // Add hardcoded offsets that are known to be consistent
        finalOffsets["ByteCode"]["Pointer"] = 0x10;
        finalOffsets["ByteCode"]["Size"] = 0x20;
        finalOffsets["Instance"]["ClassName"] = 0x8;
        finalOffsets["Instance"]["ChildrenEnd"] = 0x8;
        finalOffsets["Instance"]["ClassDescriptor"] = 0x18;
        finalOffsets["Instance"]["AttributeList"] = 0x18;
        finalOffsets["Instance"]["AttributeContainer"] = 0x48;
        finalOffsets["Instance"]["AttributeToNext"] = 0x58;
        finalOffsets["Instance"]["Name"] = 0xB0;
        finalOffsets["PrimitiveFlags"]["Anchored"] = 0x2;
        finalOffsets["PrimitiveFlags"]["CanCollide"] = 0x8;
        finalOffsets["PrimitiveFlags"]["CanTouch"] = 0x10;
        finalOffsets["FakeDataModel"]["Pointer"] = 0x7D909F8;
        finalOffsets["FakeDataModel"]["RealDataModel"] = 0x1C0;
        finalOffsets["VisualEngine"]["Pointer"] = 0x79449E0;
    }

    void ExtractVersion() {
        size_t pos = filePath.find("version-");
        if (pos != std::string::npos) {
            size_t end = filePath.find("\\", pos);
            if (end != std::string::npos) {
                robloxVersion = filePath.substr(pos, end - pos);
            }
            else {
                robloxVersion = filePath.substr(pos);
            }
        }
        else {
            robloxVersion = "unknown";
        }
    }

    void WriteHeader(const std::string& outputPath) {
        std::ofstream out(outputPath);
        if (!out.is_open()) return;

        out << "#pragma once\n";
        out << "#include <cstdint>\n\n";
        out << "// clang-format off\n";
        out << "namespace offsets {\n";
        out << "    inline constexpr const char* roblox_version = \"" << robloxVersion << "\";\n\n";

        // Define all namespaces in the correct order
        std::vector<std::string> namespaces = {
            "Atmosphere", "BasePart", "BloomEffect", "ByteCode", "Camera",
            "CharacterMesh", "DataModel", "FakeDataModel", "GuiBase2D", "GuiObject",
            "Humanoid", "InputObject", "Instance", "Lighting", "LocalScript",
            "MaterialColors", "MeshPart", "ModuleScript", "MouseService", "Player",
            "Players", "Primitive", "PrimitiveFlags", "ProximityPrompt", "RenderView",
            "Sky", "SpecialMesh", "Team", "Terrain", "TextButton", "TextLabel",
            "Tool", "Value", "VisualEngine", "Workspace", "World"
        };

        int totalFound = 0;
        for (const auto& ns : namespaces) {
            if (finalOffsets.find(ns) != finalOffsets.end() && !finalOffsets[ns].empty()) {
                out << "    namespace " << ns << " {\n";
                for (const auto& [name, value] : finalOffsets[ns]) {
                    out << "        inline constexpr uintptr_t " << name << " = 0x"
                        << std::hex << value << std::dec << ";\n";
                    totalFound++;
                }
                out << "    }\n\n";
            }
        }

        out << "} // namespace offsets\n";
        out << "// clang-format on\n";

        out.close();
        std::cout << "[+] Found " << totalFound << " offsets\n";
    }

public:
    RobloxDumper(const std::string& path) : filePath(path) {}

    bool Dump() {
        auto startTime = std::chrono::high_resolution_clock::now();

        std::cout << "[*] Loading: " << filePath << std::endl;
        if (!LoadFile()) {
            std::cerr << "Failed to load file" << std::endl;
            return false;
        }

        std::cout << "[*] Parsing PE..." << std::endl;
        if (!ParsePE()) {
            std::cerr << "Invalid PE file" << std::endl;
            return false;
        }

        std::cout << "[*] Building memory image..." << std::endl;
        BuildMemoryImage();

        std::cout << "[*] Image Base: 0x" << std::hex << imageBase << std::dec << std::endl;
        std::cout << "[*] Entry Point: 0x" << std::hex << entryPoint << std::dec << std::endl;

        ExtractVersion();

        // Run all scanners
        FindOffsetsViaDisplacement();
        FindOffsetsViaStrings();
        FindOffsetsViaVTables();
        FindOffsetsViaConstants();
        ResolveOffsets();

        std::string outputPath = filePath + "_offsets.hpp";
        WriteHeader(outputPath);

        auto endTime = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

        std::cout << "[+] Dumped to " << outputPath << std::endl;
        std::cout << "[+] Time: " << elapsed.count() / 1000.0 << " seconds" << std::endl;

        return true;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "Roblox Static Offset Dumper - Advanced Scanner\n";
    std::cout << "==============================================\n\n";

    if (argc != 2) {
        std::cout << "Drag and drop RobloxPlayerBeta.exe onto this exe\n";
        std::cout << "\nPress Enter...";
        std::cin.get();
        return 1;
    }

    RobloxDumper dumper(argv[1]);
    if (!dumper.Dump()) {
        std::cerr << "\n[-] Dump failed" << std::endl;
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.get();
    return 0;
}