import {Libg} from "../../libs/Libg";

// Static instances
const Settings_instance = Libg.offset(0x103B738, 0xEE5C38);

// Native functions
const Settings_setSelectedLanguage = new NativeFunction( // "Lng" -> 
    Libg.offset(0x9AB89C, 0x12430), 'void', ['pointer', 'pointer']
);

export class Settings {
    static get instance(): NativePointer {
        return Settings_instance.readPointer();
    }

    static setSelectedLanguage(language: string) {
        Settings_setSelectedLanguage(this.instance, language.scptr());
    }
}
