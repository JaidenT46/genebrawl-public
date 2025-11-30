import {Libg} from "../../../libs/Libg";

const LogicMath_getAngle = new NativeFunction(
    Libg.offset(0xA9AAB0, 0x9F576C), 'int', ['int', 'int'] // search by hex "11 12 12 13 13 13 14 14"
);

export class LogicMath {
    static getRotatedX(x: number, y: number, angle: number) {
        return (x * Math.cos(angle) - y * Math.sin(angle)) / 1024;
    }

    static getRotatedY(x: number, y: number, angle: number) {
        return (x * Math.sin(angle) + y * Math.cos(angle)) / 1024;
    }

    static getAngle(x: number, y: number) {
        if (!x && !y) return 0;

        return LogicMath_getAngle(x, y); // TODO: rewrite

        /*
        if (x == 0 && y == 0)
            {
                return 0;
            }
    
            if (x > 0 && y >= 0)
            {
                if (y >= x)
                {
                    return 90 - LogicMath.AtanTable[(x << 7) / y];
                }
    
                return LogicMath.AtanTable[(y << 7) / x];
            }
    
            int num = LogicMath.Abs(x);
    
            if (x <= 0 && y > 0)
            {
                if (num < y)
                {
                    return 90 + LogicMath.AtanTable[(num << 7) / y];
                }
    
                return 180 - LogicMath.AtanTable[(y << 7) / num];
            }
    
            int num2 = LogicMath.Abs(y);
    
            if (x < 0 && y <= 0)
            {
                if (num2 >= num)
                {
                    if (num2 == 0)
                    {
                        return 0;
                    }
    
                    return 270 - LogicMath.AtanTable[(num << 7) / num2];
                }
    
                return 180 + LogicMath.AtanTable[(num2 << 7) / num];
            }
    
            if (num < num2)
            {
                return 270 + LogicMath.AtanTable[(num << 7) / num2];
            }
    
            if (num == 0)
            {
                return 0;
            }
    
            return LogicMath.NormalizeAngle360(360 - LogicMath.AtanTable[(num2 << 7) / num]);
            */
    }

    static max(min: number, max: number) {
        return min <= max ? max : min;
    }
}