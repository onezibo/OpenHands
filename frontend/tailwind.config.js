/** @type {import('tailwindcss').Config} */
import { heroui } from "@heroui/react";
import typography from "@tailwindcss/typography";

export default {
  theme: {
    extend: {
      colors: {
        // 苹果风格配色方案 - 暗色为主
        primary: {
          DEFAULT: "#0A84FF", // 苹果蓝色（暗色模式优化）
          50: "#E6F3FF",
          100: "#CCE7FF",
          200: "#99CFFF",
          300: "#66B7FF",
          400: "#339FFF",
          500: "#0A84FF",
          600: "#0056CC",
          700: "#003D99",
          800: "#002466",
          900: "#000B33"
        },
        secondary: {
          DEFAULT: "#5E5CE6", // 苹果紫色（暗色优化）
          50: "#F0F0FF",
          100: "#E0E0FF",
          200: "#C2C1FF",
          300: "#A3A1FF",
          400: "#8480FF",
          500: "#5E5CE6",
          600: "#4644AB",
          700: "#343380",
          800: "#222255",
          900: "#11112B"
        },
        success: {
          DEFAULT: "#32D74B", // 苹果绿色（暗色优化）
          50: "#E8F8ED",
          100: "#D1F1DB",
          200: "#A3E3B7",
          300: "#75D593",
          400: "#47C76F",
          500: "#32D74B",
          600: "#2A9F47",
          700: "#1F7735",
          800: "#154F23",
          900: "#0A2712"
        },
        danger: {
          DEFAULT: "#FF453A", // 苹果红色（暗色优化）
          50: "#FFE8E6",
          100: "#FFD1CD",
          200: "#FFA39B",
          300: "#FF7569",
          400: "#FF4737",
          500: "#FF453A",
          600: "#CC2F26",
          700: "#99231D",
          800: "#661713",
          900: "#330C0A"
        },
        warning: {
          DEFAULT: "#FF9F0A", // 苹果橙色（暗色优化）
          50: "#FFF4E6",
          100: "#FFE9CC",
          200: "#FFD399",
          300: "#FFBD66",
          400: "#FFA733",
          500: "#FF9F0A",
          600: "#CC7700",
          700: "#995900",
          800: "#663B00",
          900: "#331E00"
        },

        // 苹果暗色主题灰色调
        gray: {
          50: "#FFFFFF",   // 纯白文本
          100: "#F2F2F7",  // 最亮文本
          200: "#E5E5EA",  // 次级文本
          300: "#C7C7CC",  // 三级文本
          400: "#AEAEB2",  // 占位符文本
          500: "#8E8E93",  // 分割线
          600: "#6D6D70",  // 非活跃文本
          700: "#48484A",  // 边框
          800: "#3A3A3C",  // 次级背景
          850: "#2C2C2E",  // 主要背景
          900: "#1C1C1E",  // 深背景
          950: "#000000"   // 最深背景
        },

        // 苹果暗色主题背景
        background: {
          primary: "#000000",      // 主背景 - 纯黑
          secondary: "#1C1C1E",    // 次级背景
          tertiary: "#2C2C2E",     // 三级背景
          elevated: "#3A3A3C"      // 悬浮背景
        },

        // 苹果暗色主题表面
        surface: {
          primary: "#1C1C1E",      // 主表面
          secondary: "#2C2C2E",    // 次级表面
          tertiary: "#3A3A3C",     // 三级表面
          elevated: "#48484A"      // 悬浮表面
        },

        // 文本颜色
        text: {
          primary: "#FFFFFF",      // 主文本 - 纯白
          secondary: "#E5E5EA",    // 次级文本
          tertiary: "#AEAEB2",     // 三级文本
          quaternary: "#6D6D70"    // 四级文本
        },

        // 毛玻璃背景色 - 优化对比度
        glass: {
          dark: "rgba(28, 28, 30, 0.9)",        // 更不透明的背景
          "dark-heavy": "rgba(44, 44, 46, 0.95)", // 重毛玻璃
          "dark-light": "rgba(28, 28, 30, 0.7)",  // 轻毛玻璃
          "dark-border": "rgba(84, 84, 88, 0.4)"  // 边框
        },

        // 兼容原有颜色命名 (确保不破坏现有组件)
        base: "#000000",                    // 主背景
        "base-secondary": "#1C1C1E",        // 次级背景
        content: "#FFFFFF",                 // 主文本
        "content-2": "#E5E5EA",            // 次级文本
        tertiary: "#48484A",               // 边框/输入框
        "tertiary-light": "#6D6D70",       // 轻边框
        basic: "#AEAEB2",                  // 基础文本
        logo: "#0A84FF"                    // Logo颜色
      },

      backdropBlur: {
        xs: "2px",
        sm: "4px",
        DEFAULT: "8px",
        md: "12px",
        lg: "16px",
        xl: "24px",
        "2xl": "40px",
        "3xl": "64px"
      },

      backgroundColor: {
        "glass-dark": "rgba(28, 28, 30, 0.9)",
        "glass-dark-heavy": "rgba(44, 44, 46, 0.95)",
        "glass-dark-light": "rgba(28, 28, 30, 0.7)"
      },

      borderColor: {
        "glass-dark": "rgba(84, 84, 88, 0.4)",
        "glass-dark-light": "rgba(84, 84, 88, 0.2)"
      },

      boxShadow: {
        'glass': '0 8px 32px 0 rgba(0, 0, 0, 0.5)',
        'glass-sm': '0 2px 8px 0 rgba(0, 0, 0, 0.3)',
        'glass-lg': '0 16px 64px 0 rgba(0, 0, 0, 0.6)',
        'apple': '0 4px 16px rgba(0, 0, 0, 0.3)',
        'apple-lg': '0 8px 32px rgba(0, 0, 0, 0.4)',
        'glow': '0 0 20px rgba(10, 132, 255, 0.3)' // 蓝色光晕
      },

      animation: {
        'glass-shimmer': 'glass-shimmer 2s ease-in-out infinite alternate',
        'glow': 'glow 2s ease-in-out infinite alternate'
      },

      keyframes: {
        'glass-shimmer': {
          '0%': { 'backdrop-filter': 'blur(20px) brightness(1)' },
          '100%': { 'backdrop-filter': 'blur(24px) brightness(1.1)' }
        },
        'glow': {
          '0%': { 'box-shadow': '0 0 20px rgba(10, 132, 255, 0.3)' },
          '100%': { 'box-shadow': '0 0 30px rgba(10, 132, 255, 0.5)' }
        }
      }
    },
  },
  darkMode: "class",
  plugins: [
    typography,
    // 苹果暗色风格毛玻璃效果插件
    function ({ addUtilities }) {
      const glassUtilities = {
        '.glass-apple': {
          'backdrop-filter': 'blur(20px) saturate(180%)',
          'background-color': 'rgba(28, 28, 30, 0.9)',
          'border': '1px solid rgba(84, 84, 88, 0.4)',
          'box-shadow': '0 8px 32px 0 rgba(0, 0, 0, 0.5)'
        },
        '.glass-apple-heavy': {
          'backdrop-filter': 'blur(24px) saturate(180%)',
          'background-color': 'rgba(44, 44, 46, 0.95)',
          'border': '1px solid rgba(84, 84, 88, 0.6)',
          'box-shadow': '0 12px 48px 0 rgba(0, 0, 0, 0.6)'
        },
        '.glass-apple-light': {
          'backdrop-filter': 'blur(12px) saturate(150%)',
          'background-color': 'rgba(28, 28, 30, 0.7)',
          'border': '1px solid rgba(84, 84, 88, 0.2)',
          'box-shadow': '0 4px 16px 0 rgba(0, 0, 0, 0.3)'
        },
        '.glass-sidebar': {
          'backdrop-filter': 'blur(24px) saturate(180%)',
          'background-color': 'rgba(44, 44, 46, 0.95)',
          'border-right': '1px solid rgba(84, 84, 88, 0.3)',
          'box-shadow': '4px 0 24px 0 rgba(0, 0, 0, 0.4)'
        },
        '.shadow-glass': {
          'box-shadow': '0 8px 32px 0 rgba(0, 0, 0, 0.5)'
        },
        '.shadow-glass-lg': {
          'box-shadow': '0 16px 64px 0 rgba(0, 0, 0, 0.6)'
        },
        '.shadow-glow': {
          'box-shadow': '0 0 20px rgba(10, 132, 255, 0.3)'
        }
      }

      addUtilities(glassUtilities)
    }
  ],
};
