import {Libc} from "../../../libs/Libc";
import {Libg} from "../../../libs/Libg";
import {MovieClip} from "../MovieClip";
import {DropGUIContainer} from "./DropGUIContainer";

const GameSliderComponent_GameSliderComponent = new NativeFunction( // "SliderTick"
    Libg.offset(0x4C3580, 0xAC724), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer', 'bool']
);

const GameSliderComponent_setValueBounds = new NativeFunction( // xref from GameSliderComponent ctor, function with args v*, 3, 60
    Libg.offset(0x4C3D34, 0xACE48), 'void', ['pointer', 'int', 'int']
);

const GameSliderComponent_setMaxValueLabel = new NativeFunction( // xref from GameSliderComponent ctor, function with "60+" arg
    Libg.offset(0x4C3D3C, 0xACE50), 'void', ['pointer', 'pointer']
);

const GameSliderComponent_update = new NativeFunction( // GameSliderComponent vtable, 2nd from end.
    Libg.offset(0x4C3BCC, 0xACCC4), 'void', ['pointer']
);

const currentValueOffset = 192;

const GameSliderComponent_allocSize = 336;

export class GameSliderComponent extends DropGUIContainer {
    private bgMovieClip: MovieClip;
    private sliderMovieClip: MovieClip;
    private bubbleMovieClip: MovieClip | undefined;

    constructor(bg: MovieClip, slider: MovieClip, bubble: MovieClip | number) {
        const instance = Libc.malloc(GameSliderComponent_allocSize);

        const sliderInstance = GameSliderComponent_GameSliderComponent(
            instance,
            bg.instance,
            slider.instance,
            bubble instanceof MovieClip ? bubble.instance : NULL,
            typeof bubble === "number" ? bubble : 0
        );

        super(sliderInstance);
        this.bgMovieClip = bg;
        this.sliderMovieClip = slider;
        if (typeof bubble !== "number") {
            this.bubbleMovieClip = bubble;
        }
    }

    setValueBounds(min: number, max: number) {
        GameSliderComponent_setValueBounds(this.instance, min, max);
    }

    setMaxValueLabel(text: string) {
        GameSliderComponent_setMaxValueLabel(this.instance, text.scptr());
    }

    setCurrentValue(value: number) {
        this.instance.add(currentValueOffset).writeInt(value);
    }

    getCurrentValue() {
        return this.instance.add(currentValueOffset).readInt();
    }

    setCurrentValueToTextField() {
        if (this.bubbleMovieClip && !this.bubbleMovieClip!.instance.isNull()) {
            const textField = this.bubbleMovieClip!.getTextFieldByName("age_txt");
            textField?.setText(this.getCurrentValue().toString());
        }
    }

    update() {
        GameSliderComponent_update(this.instance);
    }

    getBgMovieClip() {
        return this.bgMovieClip;
    }
}
