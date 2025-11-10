# -*- coding: utf-8 -*-

"""
HTML处理工具模块
"""

import re
import logging
from typing import List, Dict, Optional
from bs4 import BeautifulSoup, Comment

logger = logging.getLogger('YuanZhao.utils.html')

def clean_html(html_content: str) -> str:
    """
    清理HTML内容，去除空白字符等
    
    Args:
        html_content: HTML内容
    
    Returns:
        清理后的HTML内容
    """
    try:
        # 移除多余的空白字符
        html_content = re.sub(r'\s+', ' ', html_content)
        # 移除首尾空白
        html_content = html_content.strip()
        return html_content
    except Exception as e:
        logger.error(f"清理HTML失败: {str(e)}")
        return html_content

def extract_html_comments(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML注释
    
    Args:
        html_content: HTML内容
    
    Returns:
        注释列表，每项包含注释内容和位置
    """
    comments = []
    
    try:
        # 使用正则表达式提取注释
        comment_pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
        matches = comment_pattern.finditer(html_content)
        
        for match in matches:
            comment_content = match.group(1)
            start_pos = match.start(0)
            end_pos = match.end(0)
            
            comments.append({
                'content': comment_content.strip(),
                'position': (start_pos, end_pos)
            })
    
    except Exception as e:
        logger.error(f"提取HTML注释失败: {str(e)}")
    
    return comments

def extract_script_tags(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML中的script标签
    
    Args:
        html_content: HTML内容
    
    Returns:
        script标签列表
    """
    scripts = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        script_tags = soup.find_all('script')
        
        for script in script_tags:
            script_info = {
                'src': script.get('src', ''),
                'content': script.string or '',
                'type': script.get('type', ''),
                'language': script.get('language', '')
            }
            
            # 获取script标签的原始字符串
            if script:  # 确保script不为None
                script_info['original_tag'] = str(script)
            else:
                script_info['original_tag'] = ''
                
            scripts.append(script_info)
    
    except Exception as e:
        logger.error(f"提取script标签失败: {str(e)}")
        
        # 如果BeautifulSoup失败，尝试使用正则表达式
        try:
            script_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
            matches = script_pattern.finditer(html_content)
            
            for match in matches:
                scripts.append({
                    'src': '',
                    'content': match.group(1) or '',
                    'type': '',
                    'language': '',
                    'original_tag': match.group(0)
                })
        except Exception as fallback_error:
            logger.error(f"正则提取script标签也失败: {str(fallback_error)}")
    
    return scripts

def extract_link_tags(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML中的link标签
    
    Args:
        html_content: HTML内容
    
    Returns:
        link标签列表
    """
    links = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        link_tags = soup.find_all('link')
        
        for link in link_tags:
            links.append({
                'href': link.get('href', ''),
                'rel': link.get('rel', ''),
                'type': link.get('type', ''),
                'original_tag': str(link) if link else ''
            })
    
    except Exception as e:
        logger.error(f"提取link标签失败: {str(e)}")
    
    return links

def extract_meta_tags(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML中的meta标签
    
    Args:
        html_content: HTML内容
    
    Returns:
        meta标签列表
    """
    metas = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        meta_tags = soup.find_all('meta')
        
        for meta in meta_tags:
            meta_info = {
                'name': meta.get('name', ''),
                'content': meta.get('content', ''),
                'http-equiv': meta.get('http-equiv', ''),
                'charset': meta.get('charset', ''),
                'original_tag': str(meta) if meta else ''
            }
            metas.append(meta_info)
    
    except Exception as e:
        logger.error(f"提取meta标签失败: {str(e)}")
    
    return metas

def extract_iframe_tags(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML中的iframe标签
    
    Args:
        html_content: HTML内容
    
    Returns:
        iframe标签列表
    """
    iframes = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        iframe_tags = soup.find_all('iframe')
        
        for iframe in iframe_tags:
            iframes.append({
                'src': iframe.get('src', ''),
                'width': iframe.get('width', ''),
                'height': iframe.get('height', ''),
                'style': iframe.get('style', ''),
                'original_tag': str(iframe) if iframe else ''
            })
    
    except Exception as e:
        logger.error(f"提取iframe标签失败: {str(e)}")
    
    return iframes

def extract_all_tags(html_content: str, tag_name: str) -> List[BeautifulSoup]:
    """
    提取指定标签的所有实例
    
    Args:
        html_content: HTML内容
        tag_name: 标签名称
    
    Returns:
        标签列表
    """
    tags = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        tags = soup.find_all(tag_name)
    except Exception as e:
        logger.error(f"提取{tag_name}标签失败: {str(e)}")
    
    return tags

def get_dom_structure(html_content: str, max_depth: int = 3) -> Dict:
    """
    获取DOM结构概览
    
    Args:
        html_content: HTML内容
        max_depth: 最大深度
    
    Returns:
        DOM结构字典
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        def _process_element(element, depth):
            if depth > max_depth:
                return {}
            
            tag_info = {
                'tag': element.name,
                'attributes': {k: v for k, v in element.attrs.items()},
                'children': []
            }
            
            for child in element.children:
                if hasattr(child, 'name') and child.name:
                    tag_info['children'].append(_process_element(child, depth + 1))
            
            return tag_info
        
        return _process_element(soup.find('html') or soup, 0)
        
    except Exception as e:
        logger.error(f"获取DOM结构失败: {str(e)}")
        return {}

def find_hidden_elements(html_content: str) -> List[Dict[str, str]]:
    """
    查找可能被隐藏的元素
    
    Args:
        html_content: HTML内容
    
    Returns:
        隐藏元素列表
    """
    hidden_elements = []
    
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # 查找可能隐藏的元素
        for element in soup.find_all():
            # 检查style属性
            style = element.get('style', '').lower()
            
            if any(hidden in style for hidden in ['display:none', 'visibility:hidden', 'opacity:0']):
                hidden_elements.append({
                    'tag': element.name,
                    'style': style,
                    'content': element.get_text(),
                    'original_tag': str(element) if element else ''
                })
            
            # 检查hidden属性
            if element.get('hidden') is not None:
                hidden_elements.append({
                    'tag': element.name,
                    'reason': 'hidden attribute',
                    'content': element.get_text(),
                    'original_tag': str(element) if element else ''
                })
    
    except Exception as e:
        logger.error(f"查找隐藏元素失败: {str(e)}")
    
    return hidden_elements

def extract_text_from_html(html_content: str) -> str:
    """
    从HTML中提取纯文本
    
    Args:
        html_content: HTML内容
    
    Returns:
        提取的纯文本
    """
    try:
        soup = BeautifulSoup(html_content, 'lxml')
        
        # 移除script和style标签
        for script in soup(['script', 'style']):
            if script:
                script.decompose()
        
        # 提取文本
        text = soup.get_text(separator=' ', strip=True)
        
        # 清理空白字符
        text = re.sub(r'\s+', ' ', text)
        
        return text
        
    except Exception as e:
        logger.error(f"提取HTML文本失败: {str(e)}")
        return html_content

def remove_html_tags(html_content: str, keep_whitespace: bool = False) -> str:
    """
    移除HTML标签
    
    Args:
        html_content: HTML内容
        keep_whitespace: 是否保留空白
    
    Returns:
        移除标签后的文本
    """
    try:
        # 使用正则表达式移除标签
        text = re.sub(r'<[^>]+>', '', html_content)
        
        if not keep_whitespace:
            # 移除多余的空白字符
            text = re.sub(r'\s+', ' ', text).strip()
        
        return text
        
    except Exception as e:
        logger.error(f"移除HTML标签失败: {str(e)}")
        return html_content

def get_character_encoding(html_content: str) -> Optional[str]:
    """
    获取HTML文档的字符编码
    
    Args:
        html_content: HTML内容
    
    Returns:
        字符编码
    """
    try:
        # 检查meta标签中的charset
        charset_match = re.search(r'<meta[^>]+charset=["\']?([^"\'>\s]+)', html_content, re.IGNORECASE)
        if charset_match:
            return charset_match.group(1).lower()
        
        # 检查http-equiv中的content-type
        content_type_match = re.search(r'<meta[^>]+http-equiv=["\']?content-type["\']?[^>]*content=["\']?[^"\']*charset=([^"\'>\s;]+)', html_content, re.IGNORECASE)
        if content_type_match:
            return content_type_match.group(1).lower()
        
        return None
        
    except Exception as e:
        logger.error(f"获取字符编码失败: {str(e)}")
        return None

# 兼容性函数，为了支持html_detector.py中的导入
def extract_comments(html_content: str) -> List[Dict[str, str]]:
    """
    提取HTML注释（extract_html_comments的别名）
    
    Args:
        html_content: HTML内容
    
    Returns:
        注释列表
    """
    return extract_html_comments(html_content)
    