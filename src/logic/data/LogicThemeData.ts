import {Libg} from "../../libs/Libg";
import {LogicData} from "./LogicData";
import {GeneAssets} from "../../gene/GeneAssets";

const LogicThemeData_isDisabled = new NativeFunction( // "Active theme is marked disabled! theme:"
    Libg.offset(0x8F2C98, 0x41EFD8), 'bool', ['pointer']
);

const LogicThemeData_getFileName = new NativeFunction( // "HomeScreen::enter - active theme sc file doesn't exist! theme:"
    Libg.offset(0x8F2CA8, 0x41EFE8), 'pointer', ['pointer']
);

const LogicThemeData_getExportName = new NativeFunction( // "Active theme is marked disabled! theme:"
    Libg.offset(0x8F2CB8, 0x41EFF8), 'pointer', ['pointer']
);

const LogicThemeData_getParticleFileName = new NativeFunction(
    Libg.offset(0x8F2CC8, 0x41F008), 'pointer', ['pointer']
);

const LogicThemeData_getParticleExportName = new NativeFunction(
    Libg.offset(0x8F2CD8, 0x41F018), 'pointer', ['pointer']
);

const LogicThemeData_getParticleStyle = new NativeFunction(
    Libg.offset(0x8F2CE8, 0x41F028), 'pointer', ['pointer']
);

const LogicThemeData_getParticleVariations = new NativeFunction(
    Libg.offset(0x8F2CF8, 0x41F038), 'int', ['pointer']
);

const musicOffset = 88;

export class LogicThemeData extends LogicData {
    constructor(instance: NativePointer) {
        super(instance);
    }

    isDisabled() {
        return LogicThemeData.isDisabled(this.instance);
    }

    getFileName(): string {
        return LogicThemeData.getFileName(this.instance).fromsc();
    }

    getExportName(): string {
        return LogicThemeData.getExportName(this.instance).fromsc();
    }

    getThemeMusic(): NativePointer {
        return LogicThemeData.getMusic(this.instance);
    }

    static getFileName(themeData: NativePointer): NativePointer {
        return LogicThemeData_getFileName(themeData);
    }

    static getExportName(themeData: NativePointer): NativePointer {
        return LogicThemeData_getExportName(themeData);
    }

    static isDisabled(themeData: NativePointer): boolean {
        return Boolean(
            LogicThemeData_isDisabled(themeData)
        );
    }

    static getMusic(themeData: NativePointer): NativePointer {
        return themeData.add(musicOffset).readPointer();
    }

    static patch() {
        return; //snow is disabled until next winter!
        const snowUi = "sc/old_ui.sc";

        try {
            Interceptor.replace(LogicThemeData_getParticleExportName, new NativeCallback((themeData) => {
                if (!GeneAssets.wasLoaded(snowUi)) return LogicThemeData_getParticleExportName(themeData);

                return "particle_snow_".scptr();
            }, 'pointer', ['pointer']));

            Interceptor.replace(LogicThemeData_getParticleVariations, new NativeCallback((themeData) => {
                if (!GeneAssets.wasLoaded(snowUi)) return LogicThemeData_getParticleVariations(themeData);

                return 2;
            }, 'int', ['pointer']));

            Interceptor.replace(LogicThemeData_getParticleFileName, new NativeCallback((themeData) => {
                if (!GeneAssets.wasLoaded(snowUi)) return LogicThemeData_getParticleFileName(themeData);

                return "sc/old_ui.sc".scptr();
            }, 'pointer', ['pointer']));

            Interceptor.replace(LogicThemeData_getParticleStyle, new NativeCallback((themeData) => {
                if (!GeneAssets.wasLoaded(snowUi)) return LogicThemeData_getParticleStyle(themeData);

                return "Snow".scptr();
            }, 'pointer', ['pointer']));

            const oldUI = Memory.allocUtf8String(snowUi);

            Interceptor.attach(Libg.offset(-1, -1), function () {
                const context = this.context as Arm64CpuContext;

                if (GeneAssets.wasLoaded(snowUi)) {
                    context.x23 = oldUI;
                }
            });
        } catch (e) {
            console.error("Something went wrong with snow!\n", e);
        }
    }
}