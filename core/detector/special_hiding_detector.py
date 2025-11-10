# -*- coding: utf-8 -*-

"""
特殊隐藏技术检测器模块
"""

import re
import logging
from typing import List, Dict

logger = logging.getLogger('YuanZhao.detector.special_hiding')

class SpecialHidingDetector:
    """特殊隐藏技术检测器"""
    
    def __init__(self, config):
        self.config = config
        self._init_patterns()
    
    def _init_patterns(self):
        """初始化正则表达式模式"""
        # 零宽字符模式
        self.zero_width_chars = [
            '\u200B',  # 零宽空格
            '\u200C',  # 零宽不连字
            '\u200D',  # 零宽连字
            '\u2060',  # 字连接符
            '\uFEFF',  # 字节顺序标记
        ]
        self.zero_width_pattern = re.compile('|'.join(re.escape(c) for c in self.zero_width_chars))
        
        # 空白字符堆积
        self.whitespace_pattern = re.compile(r'(\s|\t|\r|\n){10,}')
        
        # 颜色隐藏（颜色接近背景色）
        self.color_pattern = re.compile(
            r'color\s*:\s*(#\w{3,6}|rgba?\([^)]+\))',
            re.IGNORECASE
        )
        self.background_color_pattern = re.compile(
            r'background-color\s*:\s*(#\w{3,6}|rgba?\([^)]+\))',
            re.IGNORECASE
        )
        
        # 绝对定位隐藏（离屏元素）
        self.absolute_position_pattern = re.compile(
            r'position\s*:\s*absolute.*?(left|top|bottom|right)\s*:\s*(-?\d+(?:\.\d+)?(?:px|em|%)?)',
            re.IGNORECASE | re.DOTALL
        )
        
        # 字体大小隐藏
        self.font_size_pattern = re.compile(
            r'font-size\s*:\s*(0|0\.\d+)',
            re.IGNORECASE
        )
        
        # 文本缩进隐藏
        self.text_indent_pattern = re.compile(
            r'text-indent\s*:\s*(-\d+(?:\.\d+)?(?:px|em|%))',
            re.IGNORECASE
        )
        
        # 透明度隐藏
        self.opacity_pattern = re.compile(
            r'opacity\s*:\s*(0|0\.\d+)',
            re.IGNORECASE
        )
        self.visibility_pattern = re.compile(
            r'visibility\s*:\s*hidden',
            re.IGNORECASE
        )
        self.display_none_pattern = re.compile(
            r'display\s*:\s*none',
            re.IGNORECASE
        )
        
        # 多层嵌套隐藏
        self.nested_elements_pattern = re.compile(
            r'<(div|span|p|a)[^>]*>\s*<(div|span|p|a)[^>]*>\s*<(div|span|p|a)[^>]*>',
            re.IGNORECASE
        )
        
        # HTML实体编码隐藏
        self.html_entity_pattern = re.compile(r'&#(\d+);|&#x([0-9a-f]+);')
        
        # 可疑的编码混合
        self.mixed_encoding_pattern = re.compile(
            r'https?://(?:[\w\-._~:/?#[\]@!$&\'()*+,;=]|%[0-9a-fA-F]{2})+',
            re.IGNORECASE
        )
    
    def detect(self, content: str, source: str) -> List[Dict]:
        """检测特殊隐藏技术"""
        results = []
        
        try:
            # 检测零宽字符
            zero_width_results = self._detect_zero_width_chars(content, source)
            results.extend(zero_width_results)
            
            # 检测空白字符堆积
            whitespace_results = self._detect_whitespace(content, source)
            results.extend(whitespace_results)
            
            # 检测颜色隐藏
            color_results = self._detect_color_hiding(content, source)
            results.extend(color_results)
            
            # 检测绝对定位隐藏
            position_results = self._detect_position_hiding(content, source)
            results.extend(position_results)
            
            # 检测字体大小隐藏
            font_size_results = self._detect_font_size_hiding(content, source)
            results.extend(font_size_results)
            
            # 检测文本缩进隐藏
            indent_results = self._detect_text_indent_hiding(content, source)
            results.extend(indent_results)
            
            # 检测透明度隐藏
            opacity_results = self._detect_opacity_hiding(content, source)
            results.extend(opacity_results)
            
            # 检测多层嵌套隐藏
            nested_results = self._detect_nested_elements(content, source)
            results.extend(nested_results)
            
            # 检测HTML实体编码隐藏
            entity_results = self._detect_html_entities(content, source)
            results.extend(entity_results)
            
        except Exception as e:
            logger.error(f"特殊隐藏技术检测失败: {str(e)}", exc_info=True)
        
        return results
    
    def _detect_zero_width_chars(self, content: str, source: str) -> List[Dict]:
        """检测零宽字符"""
        results = []
        
        matches = list(self.zero_width_pattern.finditer(content))
        if matches:
            # 收集所有零宽字符的上下文
            context = self._get_context(content, matches[0].start(), matches[-1].end(), 100)
            
            # 解码隐藏内容（如果可能）
            hidden_content = self._extract_hidden_content(content, self.zero_width_chars)
            
            results.append({
                'link': f'零宽字符隐藏 ({len(matches)}个字符)',
                'source': source,
                'type': 'zero_width_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': context,
                'hidden_content': hidden_content if hidden_content else None
            })
        
        return results
    
    def _detect_whitespace(self, content: str, source: str) -> List[Dict]:
        """检测空白字符堆积"""
        results = []
        
        for match in self.whitespace_pattern.finditer(content):
            # 检查是否在HTML标签之间或注释中
            context = self._get_context(content, match.start(), match.end(), 50)
            
            # 只有在标签之间大量空白才认为可疑
            if '<' not in context and '>' not in context:
                results.append({
                    'link': f'空白字符堆积 ({len(match.group(1))}个字符)',
                    'source': source,
                    'type': 'whitespace_hiding',
                    'detection_method': 'regex',
                    'risk_level': '中',
                    'context': context
                })
        
        return results
    
    def _detect_color_hiding(self, content: str, source: str) -> List[Dict]:
        """检测颜色隐藏"""
        results = []
        
        # 找到所有颜色定义
        for color_match in self.color_pattern.finditer(content):
            color = color_match.group(1)
            
            # 在同一段落中查找背景颜色
            start_pos = max(0, color_match.start() - 200)
            end_pos = min(len(content), color_match.end() + 200)
            segment = content[start_pos:end_pos]
            
            bg_match = self.background_color_pattern.search(segment)
            if bg_match:
                bg_color = bg_match.group(1)
                
                # 如果颜色非常接近背景色，标记为可疑
                if self._colors_are_similar(color, bg_color):
                    results.append({
                        'link': f'颜色隐藏 (文字:{color}, 背景:{bg_color})',
                        'source': source,
                        'type': 'color_hiding',
                        'detection_method': 'regex',
                        'risk_level': '高',
                        'context': self._get_context(content, color_match.start(), color_match.end())
                    })
        
        return results
    
    def _detect_position_hiding(self, content: str, source: str) -> List[Dict]:
        """检测绝对定位隐藏"""
        results = []
        
        for match in self.absolute_position_pattern.finditer(content):
            direction = match.group(1).lower()
            value = match.group(2)
            
            # 提取数值部分
            num_value = float(re.search(r'([-\d.]+)', value).group(1))
            
            # 如果位置在屏幕外（非常大的负值或正值）
            if abs(num_value) > 1000:
                results.append({
                    'link': f'绝对定位隐藏 ({direction}:{value})',
                    'source': source,
                    'type': 'position_hiding',
                    'detection_method': 'regex',
                    'risk_level': '高',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return results
    
    def _detect_font_size_hiding(self, content: str, source: str) -> List[Dict]:
        """检测字体大小隐藏"""
        results = []
        
        for match in self.font_size_pattern.finditer(content):
            size = match.group(1)
            
            results.append({
                'link': f'字体大小隐藏 (size:{size})',
                'source': source,
                'type': 'font_size_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return results
    
    def _detect_text_indent_hiding(self, content: str, source: str) -> List[Dict]:
        """检测文本缩进隐藏"""
        results = []
        
        for match in self.text_indent_pattern.finditer(content):
            indent = match.group(1)
            
            # 提取数值部分
            num_value = float(re.search(r'([-\d.]+)', indent).group(1))
            
            # 如果缩进很大（负值），可能是隐藏文本
            if num_value < -50:
                results.append({
                    'link': f'文本缩进隐藏 (indent:{indent})',
                    'source': source,
                    'type': 'text_indent_hiding',
                    'detection_method': 'regex',
                    'risk_level': '高',
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return results
    
    def _detect_opacity_hiding(self, content: str, source: str) -> List[Dict]:
        """检测透明度隐藏"""
        results = []
        
        # 检测opacity
        for match in self.opacity_pattern.finditer(content):
            opacity = match.group(1)
            results.append({
                'link': f'透明度隐藏 (opacity:{opacity})',
                'source': source,
                'type': 'opacity_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        # 检测visibility:hidden
        for match in self.visibility_pattern.finditer(content):
            results.append({
                'link': '可见性隐藏 (visibility:hidden)',
                'source': source,
                'type': 'visibility_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        # 检测display:none
        for match in self.display_none_pattern.finditer(content):
            results.append({
                'link': '显示隐藏 (display:none)',
                'source': source,
                'type': 'display_hiding',
                'detection_method': 'regex',
                'risk_level': '高',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return results
    
    def _detect_nested_elements(self, content: str, source: str) -> List[Dict]:
        """检测多层嵌套隐藏"""
        results = []
        
        for match in self.nested_elements_pattern.finditer(content):
            results.append({
                'link': '多层嵌套隐藏',
                'source': source,
                'type': 'nested_hiding',
                'detection_method': 'regex',
                'risk_level': '中',
                'context': self._get_context(content, match.start(), match.end())
            })
        
        return results
    
    def _detect_html_entities(self, content: str, source: str) -> List[Dict]:
        """检测HTML实体编码隐藏"""
        results = []
        
        # 计算HTML实体的密度
        entity_matches = list(self.html_entity_pattern.finditer(content))
        
        # 如果在较短的文本中有大量实体编码，可能是隐藏内容
        if len(entity_matches) > 10:
            # 尝试解码一些实体看看是否包含可疑内容
            sample = content[max(0, entity_matches[0].start() - 20):entity_matches[min(5, len(entity_matches)-1)].end() + 20]
            
            results.append({
                'link': f'HTML实体编码隐藏 ({len(entity_matches)}个实体)',
                'source': source,
                'type': 'entity_hiding',
                'detection_method': 'regex',
                'risk_level': '中',
                'context': sample
            })
        
        return results
    
    def _colors_are_similar(self, color1: str, color2: str) -> bool:
        """检查两个颜色是否相似"""
        # 这是一个简化的实现，实际应用中可能需要更复杂的颜色比较
        # 在这里我们只是检查是否完全相同或都是深色/浅色
        
        # 转换为小写以便比较
        color1 = color1.lower()
        color2 = color2.lower()
        
        # 如果完全相同，肯定是相似的
        if color1 == color2:
            return True
        
        # 检查是否都是深色（简化判断）
        dark_colors = ['#000', '#000000', 'black', 'rgb(0,0,0)']
        if color1 in dark_colors and color2 in dark_colors:
            return True
        
        # 检查是否都是白色
        white_colors = ['#fff', '#ffffff', 'white', 'rgb(255,255,255)']
        if color1 in white_colors and color2 in white_colors:
            return True
        
        return False
    
    def _extract_hidden_content(self, content: str, markers: List[str]) -> str:
        """从内容中提取使用特定标记隐藏的内容"""
        # 这个方法可以进一步扩展来提取使用零宽字符编码的隐藏内容
        # 目前只是一个简单的实现
        
        # 移除所有标记字符，看看是否有剩余的有意义内容
        clean_content = content
        for marker in markers:
            clean_content = clean_content.replace(marker, '')
        
        # 如果清理后的内容与原内容不同，返回清理后的内容（限制长度）
        if clean_content != content:
            return clean_content.strip()[:200]
        
        return None
    
    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """获取匹配内容的上下文"""
        start_context = max(0, start - context_size)
        end_context = min(len(content), end + context_size)
        
        context = content[start_context:end_context]
        context = context.replace('\n', ' ').replace('\r', ' ')
        
        # 移除零宽字符以便显示
        for char in self.zero_width_chars:
            context = context.replace(char, '')
        
        return context
        