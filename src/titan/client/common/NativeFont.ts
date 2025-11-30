import {Libg} from "../../../libs/Libg";

const NativeFont_formatString = new NativeFunction( // "NativeFont::formatString - Invalid UTF-8"
    Libg.offset(0xA1CC60, 0x965F30), 'pointer', ['pointer', 'pointer', 'float', 'float', 'int', 'float', 'bool', 'bool', 'float']
);

export class NativeFont {
    static patch() {
        Interceptor.replace(NativeFont_formatString, new NativeCallback(function(instance, a2, a3, a4, a5, a6, a7, a8, a9) {
            a8 = 1;

            return NativeFont_formatString(instance, a2, a3, a4, a5, a6, a7, a8, a9);
        }, 'pointer', ['pointer', 'pointer', 'float', 'float', 'int', 'float', 'bool', 'bool', 'float']));
    }
}